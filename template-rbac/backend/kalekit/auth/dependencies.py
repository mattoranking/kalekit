from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.client_type import ClientType
from kalekit.auth.permissions import (
    get_scopes_for_roles,
    is_any_blocked,
)
from kalekit.config import settings
from kalekit.models.user import User
from kalekit.postgres import get_db_session

bearer_scheme = HTTPBearer()

# Every access token's `aud` claim must be one of these -- accepting any
# valid ClientType (rather than one fixed audience) is what lets a
# single signing key issue tokens for web, mobile, and admin while
# still rejecting a token minted for one client from being used as if
# it were minted for another (see require_admin_client below, and #6).
_VALID_AUDIENCES = [c.value for c in ClientType]


def _signing_key_for_kid(kid: Any) -> str | None:
    """Resolve a token's `kid` header to the secret it was (or should
    have been) signed with -- the current key, or one of the previous
    keys kept around for rotation. None means "don't know this key",
    which the caller must treat as an invalid token.

    `kid` comes from the *unverified* token header, so it's arbitrary
    attacker-controlled JSON, not necessarily a string -- e.g. a list
    or dict, which would raise `TypeError: unhashable type` from the
    dict lookup below if not rejected first.
    """
    if not isinstance(kid, str) or not kid:
        return None
    if kid == settings.JWT_KID:
        return settings.JWT_SECRET_KEY
    return settings.JWT_PREVIOUS_KEYS.get(kid)


def _decode_access_token(credentials: HTTPAuthorizationCredentials) -> dict[str, Any]:
    token = credentials.credentials

    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    key = _signing_key_for_kid(kid)
    if key is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = jwt.decode(
            token,
            key,
            # Pinning the algorithm list (rather than trusting whatever
            # `alg` the token claims) is what closes the classic
            # "alg: none" / algorithm-confusion JWT attacks.
            algorithms=[settings.JWT_ALGORITHM],
            audience=_VALID_AUDIENCES,
            leeway=settings.JWT_LEEWAY_SECONDS,
            options={"require": ["exp", "aud"]},
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    # The JWT spec (and PyJWT) allows `aud` to be either a single string
    # or a list of strings; jwt.decode's `audience=_VALID_AUDIENCES`
    # check above accepts a token whose `aud` is a *list* as long as
    # one entry matches, and hands it back as-is -- i.e. `payload["aud"]`
    # could come back as e.g. `["web", "mobile"]` rather than "web".
    # This app never mints multi-audience tokens (create_access_token
    # always sets `aud` to a single client string), so reject that
    # shape here, at the one place every caller's token gets decoded,
    # rather than needing get_current_client and everything else that
    # reads `aud` to separately guard against it -- otherwise
    # `ClientType(payload["aud"])` downstream raises on the unhashable
    # list and surfaces as an unhandled 500 instead of failing closed.
    if not isinstance(payload.get("aud"), str):
        raise HTTPException(status_code=401, detail="Invalid token audience")

    return payload


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    payload = _decode_access_token(credentials)
    user_id = payload.get("sub")
    jti = payload.get("jti")
    sid = payload.get("sid")

    if await is_any_blocked(jti, user_id, sid):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    user = await session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_current_scopes(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> set[str]:
    """The permission set baked into the token at login/refresh.

    This is a convenience snapshot only -- e.g. for a frontend's own
    cheap edge checks (a Next.js middleware redirect) that can tolerate
    staleness up to whatever access-token lifetime applies to the
    caller's client (see Settings.access_token_expire_minutes). It is NOT the
    authority for backend authorization: `require_permission` below
    re-resolves the caller's permissions live against the Redis role
    cache on every request instead of trusting these baked-in scopes,
    so a role/permission change takes effect on the very next request
    rather than only once the token is refreshed (see #6).
    """
    payload = _decode_access_token(credentials)
    return set(payload.get("scopes", []))


async def get_current_client(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> ClientType:
    """Which client (web/mobile/admin) minted the current access token,
    from its `aud` claim. Decoding already restricts `aud` to one of
    ClientType's values (see _VALID_AUDIENCES), so this always
    succeeds for any token that reaches here."""
    payload = _decode_access_token(credentials)
    return ClientType(payload["aud"])


async def get_current_jti(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> str | None:
    """The current access token's unique id, for revoking it by itself
    (e.g. on logout) rather than every token the user holds."""
    payload = _decode_access_token(credentials)
    return payload.get("jti")


async def get_current_session_id(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> str | None:
    """The refresh token family (session) the current access token was
    minted from, if any -- lets /auth/sessions mark the caller's own
    session and lets password-change/reset keep it while revoking the
    rest. See create_access_token's `session_id` param."""
    payload = _decode_access_token(credentials)
    return payload.get("sid")


async def require_verified_email(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Gate for anything beyond profile / resend-verification when
    REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN is off -- unverified users
    can still log in and reach `/auth/me` and `/auth/resend-verification`,
    but not routes that depend on this."""
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Email verification required")
    return user


def require_permission(permission: str):
    """Dependency factory for RBAC checks.

    Resolves the caller's permissions live against the Redis-cached
    role lookup (get_scopes_for_roles) on every call, using the roles
    `get_current_user` just loaded fresh from the database -- it does
    NOT trust the access token's baked-in `scopes` claim. Since
    get_current_user already re-fetches the user (and its roles) from
    the DB on every request, the token's scopes bought no real caching
    benefit, only staleness: a revoked role would otherwise keep
    working for up to whatever access-token lifetime applies to that
    client (see Settings.access_token_expire_minutes). Resolving live here
    means a role or permission change applies on the very next request,
    for every client, with only the Redis role-cache TTL
    (ROLE_CACHE_TTL_SECONDS) as the remaining delay. See #6.
    """

    async def checker(
        user: Annotated[User, Depends(get_current_user)],
        session: Annotated[AsyncSession, Depends(get_db_session)],
    ) -> User:
        roles = [ur.role.name for ur in user.roles]
        scopes = await get_scopes_for_roles(session, roles)
        if permission not in scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Missing permission: {permission}",
            )
        return user

    return checker


async def require_admin_client(
    client: Annotated[ClientType, Depends(get_current_client)],
) -> None:
    """Reject any access token whose `aud` isn't `admin`, regardless of
    the permissions baked into its scopes.

    This is what actually separates the back office from the product:
    a user who holds the admin role but signed into the consumer
    web/mobile app gets a token with `aud="web"`/`"mobile"` (see
    create_access_token) that `require_permission("admin:*")` alone
    would still accept -- this dependency additionally requires the
    token to have been minted by the admin client itself. Compose it
    alongside `require_permission` on admin-only routes. See #6.
    """
    if client is not ClientType.admin:
        raise HTTPException(status_code=403, detail="Admin client required")
