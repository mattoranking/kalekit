"""
OAuth2 authorization-code flow endpoints.

GET  /oauth/{provider}/authorize  → redirect URL + state
GET  /oauth/{provider}/callback   → exchange code → JWT

State (and PKCE code_verifier for Twitter) are stored in Redis
with a short TTL to prevent CSRF and replay attacks.
"""

import secrets
from typing import Annotated

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import store_refresh_token
from kalekit.auth.service import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from kalekit.config import settings
from kalekit.oauth.client import OAUTH_PROVIDERS
from kalekit.oauth.repository import (
    OAuthAccountLinkingError,
    find_or_create_oauth_user,
)
from kalekit.postgres import get_db_session
from kalekit.redis import get_redis
from kalekit.utils.rate_limit import (
    check_and_increment,
    get_client_ip,
    rate_limit_fails_open,
    rate_limited,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/oauth", tags=["oauth"])

_STATE_TTL = 600  # 10 minutes


def _oauth_unavailable(event: str) -> HTTPException:
    """A clean 503 for a Redis failure on an OAuth path (#106).

    The CSRF state lives only in Redis, so there is nothing to degrade
    to: fail closed, but as a documented "dependency unavailable"
    response instead of an unhandled 500. Password login doesn't touch
    this state and stays available. Call from inside an `except
    RedisError` block so the traceback is attached to the log.
    """
    logger.warning(event, exc_info=True)
    return HTTPException(
        status_code=503, detail="OAuth sign-in is temporarily unavailable"
    )


async def _enforce_oauth_rate_limit(request: Request, endpoint: str) -> None:
    """Per-IP fixed-window limit shared by both OAuth endpoints, with a
    separate counter per endpoint. Raises a 429 carrying `Retry-After`;
    a Redis error inside the limiter lets the request through (the state
    store below still fails closed on its own)."""
    if not settings.RATE_LIMIT_ENABLED:
        return
    with rate_limit_fails_open(f"oauth_{endpoint}"):
        r = await get_redis()
        ip_key = f"oauth_rate:{endpoint}:ip:{get_client_ip(request)}"
        allowed = await check_and_increment(
            r,
            ip_key,
            limit=settings.OAUTH_RATE_LIMIT_PER_IP,
            window_seconds=settings.OAUTH_RATE_LIMIT_WINDOW_SECONDS,
        )
        if not allowed:
            raise rate_limited(await r.ttl(ip_key))


def _get_provider(provider: str):
    client = OAUTH_PROVIDERS.get(provider)
    if not client:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    return client


@router.get("/{provider}/authorize")
async def oauth_authorize(provider: str, request: Request):
    """Generate an authorization URL and return it to the frontend.

    The frontend redirects the user's browser to this URL.
    State is stored in Redis so the callback can validate it.
    """
    await _enforce_oauth_rate_limit(request, "authorize")
    client = _get_provider(provider)
    state = secrets.token_urlsafe(32)

    authorization_url, code_verifier = client.get_authorization_url(state)

    # Store state (and code_verifier for PKCE) in Redis
    state_data = provider
    if code_verifier:
        state_data = f"{provider}:{code_verifier}"
    try:
        r = await get_redis()
        await r.set(f"oauth_state:{state}", state_data, ex=_STATE_TTL)
    except RedisError as exc:
        raise _oauth_unavailable("oauth_state_store_failed") from exc

    return {"authorization_url": authorization_url}


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    code: Annotated[str, Query()],
    state: Annotated[str, Query()],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Handle the OAuth provider's redirect.

    1. Validate state against Redis (prevents CSRF)
    2. Exchange the authorization code for an access token
    3. Fetch the user's profile from the provider
    4. Find or create a local User + OAuthAccount link
    5. Return our own JWT pair
    """
    await _enforce_oauth_rate_limit(request, "callback")
    client = _get_provider(provider)

    # --- Validate state ---
    state_key = f"oauth_state:{state}"
    try:
        r = await get_redis()
        state_data = await r.get(state_key)
        if not state_data:
            raise HTTPException(status_code=400, detail="Invalid or expired state")

        # Delete immediately — state is single-use
        await r.delete(state_key)
    except RedisError as exc:
        raise _oauth_unavailable("oauth_state_check_failed") from exc

    # Parse code_verifier if present (Twitter PKCE)
    code_verifier: str | None = None
    if ":" in state_data:
        stored_provider, code_verifier = state_data.split(":", 1)
    else:
        stored_provider = state_data

    if stored_provider != provider:
        raise HTTPException(status_code=400, detail="State/provider mismatch")

    # --- Exchange code for token ---
    try:
        token_response = await client.exchange_code(code, code_verifier)
    except Exception:
        raise HTTPException(
            status_code=502, detail="Failed to exchange code with provider"
        )

    provider_access_token = token_response.get("access_token")
    if not provider_access_token:
        raise HTTPException(
            status_code=502, detail="Provider did not return an access token"
        )

    # --- Fetch user profile (the provider token is used here, in memory only) ---
    try:
        user_info = await client.get_user_info(provider_access_token)
    except Exception:
        raise HTTPException(
            status_code=502, detail="Failed to fetch user info from provider"
        )

    # Normalize provider-specific fields
    account_id, account_email, display_name = _extract_user_info(provider, user_info)

    # --- Find or create local user ---
    provider_email_verified = await _get_provider_email_verified(
        provider, user_info, provider_access_token, account_email
    )
    try:
        user = await find_or_create_oauth_user(
            session,
            platform=provider,
            account_id=account_id,
            account_email=account_email,
            display_name=display_name,
            provider_email_verified=provider_email_verified,
        )
    except OAuthAccountLinkingError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if settings.REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN and not user.email_verified:
        raise HTTPException(status_code=403, detail="Email verification required")

    # --- Issue our token pair ---
    access_token = create_access_token(str(user.id))
    refresh_token, expires_at = generate_refresh_token()

    # Persist it like /auth/login does -- otherwise /auth/refresh (which
    # now validates against the DB) can never find this token and every
    # OAuth-issued refresh token would be permanently unusable.
    await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
        expires_at=expires_at,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


def _extract_user_info(
    provider: str, user_info: dict
) -> tuple[str, str | None, str | None]:
    """Normalize the user ID, email, and display name from provider JSON.

    Each provider returns a different shape:
    - GitHub:  {"id": 12345, "email": "...", "name": "...", "login": "...", ...}
    - Google:  {"id": "abc", "email": "...", "name": "...", ...}
    - Twitter: {"data": {"id": "123", "username": "...", "name": "...", ...}}

    The display name is used only to name a brand-new user's default
    organization (e.g. "Jane's workspace") instead of deriving it from
    the email address, which would leak the email's local part.
    """
    if provider == "github":
        return (
            str(user_info["id"]),
            user_info.get("email"),
            user_info.get("name") or user_info.get("login"),
        )

    if provider == "google":
        return str(user_info["id"]), user_info.get("email"), user_info.get("name")

    if provider == "twitter":
        data = user_info.get("data", {})
        # Twitter doesn't expose email by default
        return (
            str(data["id"]),
            None,
            data.get("name") or data.get("username"),
        )

    raise ValueError(f"Unknown provider: {provider}")


async def _get_provider_email_verified(
    provider: str,
    user_info: dict,
    access_token: str,
    account_email: str | None,
) -> bool:
    """Does the IdP itself vouch that `account_email` is verified?

    find_or_create_oauth_user uses this to decide whether it is safe to
    link an OAuth sign-in to an existing password account (see the
    docstring there for the attack this guards against). Each provider
    is handled explicitly; an unknown one defaults to unverified.
    """
    if not account_email:
        return False

    if provider == "google":
        # Google's userinfo response includes this directly.
        return bool(user_info.get("verified_email", False))

    if provider == "github":
        # GitHub's /user endpoint doesn't carry verification status for
        # the profile email, so ask /user/emails (covered by the
        # `user:email` scope we request) and check the matching entry.
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/user/emails",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                    },
                )
                response.raise_for_status()
                emails = response.json()
        except Exception:
            return False
        return any(
            e.get("email") == account_email and e.get("verified") for e in emails
        )

    # Twitter never returns an email, so account_email is None above.
    return False
