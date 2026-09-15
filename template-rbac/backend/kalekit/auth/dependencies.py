from typing import Annotated, Any

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import is_token_blocked, is_user_blocked
from kalekit.config import settings
from kalekit.models.user import User
from kalekit.postgres import get_db_session

bearer_scheme = HTTPBearer()


def _decode_access_token(credentials: HTTPAuthorizationCredentials) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    payload = _decode_access_token(credentials)
    user_id = payload.get("sub")
    jti = payload.get("jti")

    if jti and await is_token_blocked(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    if user_id and await is_user_blocked(user_id):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    user = await session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_current_scopes(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> set[str]:
    """The permission set baked into the token at login/refresh.

    Reading it straight from the token (instead of re-resolving the
    user's roles against Redis/the DB on every request) trades a
    small staleness window -- a role change takes effect on the
    token's next refresh, not instantly -- for removing a cache/DB
    round trip from every permission check. See get_current_user for
    the escape hatch when a permission needs to be pulled immediately:
    block_token/block_all_user_tokens force the token to be re-issued
    (and its scopes re-resolved) before its natural expiry.
    """
    payload = _decode_access_token(credentials)
    return set(payload.get("scopes", []))


async def get_current_jti(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> str | None:
    """The current access token's unique id, for revoking it by itself
    (e.g. on logout) rather than every token the user holds."""
    payload = _decode_access_token(credentials)
    return payload.get("jti")


def require_permission(permission: str):
    """Dependency factory for RBAC checks."""

    async def checker(
        user: Annotated[User, Depends(get_current_user)],
        scopes: Annotated[set[str], Depends(get_current_scopes)],
    ) -> User:
        if permission not in scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Missing permission: {permission}",
            )
        return user

    return checker
