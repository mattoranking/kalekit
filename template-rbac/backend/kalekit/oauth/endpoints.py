"""
OAuth2 authorization-code flow endpoints.

GET  /oauth/{provider}/authorize  → redirect URL + state
GET  /oauth/{provider}/callback   → exchange code → JWT

State (and PKCE code_verifier for Twitter) are stored in Redis
with a short TTL to prevent CSRF and replay attacks.
"""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import get_redis, get_scopes_for_roles
from kalekit.auth.repository import store_refresh_token
from kalekit.auth.service import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from kalekit.oauth.client import OAUTH_PROVIDERS
from kalekit.oauth.repository import find_or_create_oauth_user
from kalekit.postgres import get_db_session

router = APIRouter(prefix="/oauth", tags=["oauth"])

_STATE_TTL = 600  # 10 minutes


def _get_provider(provider: str):
    client = OAUTH_PROVIDERS.get(provider)
    if not client:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    return client


@router.get("/{provider}/authorize")
async def oauth_authorize(provider: str):
    """Generate an authorization URL and return it to the frontend.

    The frontend redirects the user's browser to this URL.
    State is stored in Redis so the callback can validate it.
    """
    client = _get_provider(provider)
    state = secrets.token_urlsafe(32)

    authorization_url, code_verifier = client.get_authorization_url(state)

    # Store state (and code_verifier for PKCE) in Redis
    r = await get_redis()
    state_data = provider
    if code_verifier:
        state_data = f"{provider}:{code_verifier}"
    await r.set(f"oauth_state:{state}", state_data, ex=_STATE_TTL)

    return {"authorization_url": authorization_url}


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
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
    client = _get_provider(provider)

    # --- Validate state ---
    r = await get_redis()
    state_key = f"oauth_state:{state}"
    state_data = await r.get(state_key)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    # Delete immediately — state is single-use
    await r.delete(state_key)

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

    provider_refresh_token = token_response.get("refresh_token")

    # --- Fetch user profile ---
    try:
        user_info = await client.get_user_info(provider_access_token)
    except Exception:
        raise HTTPException(
            status_code=502, detail="Failed to fetch user info from provider"
        )

    # Normalize provider-specific fields
    account_id, account_email = _extract_user_info(provider, user_info)

    # --- Find or create local user ---
    user = await find_or_create_oauth_user(
        session,
        platform=provider,
        account_id=account_id,
        account_email=account_email,
        access_token=provider_access_token,
        refresh_token=provider_refresh_token,
    )

    # --- Issue our token pair ---
    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    access_token = create_access_token(str(user.id), list(scopes))
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


def _extract_user_info(provider: str, user_info: dict) -> tuple[str, str | None]:
    """Normalize the user ID and email from provider-specific JSON.

    Each provider returns a different shape:
    - GitHub:  {"id": 12345, "email": "...", ...}
    - Google:  {"id": "abc", "email": "...", ...}
    - Twitter: {"data": {"id": "123", "username": "...", ...}}
    """
    if provider == "github":
        return str(user_info["id"]), user_info.get("email")

    if provider == "google":
        return str(user_info["id"]), user_info.get("email")

    if provider == "twitter":
        data = user_info.get("data", {})
        return str(data["id"]), None  # Twitter doesn't expose email by default

    raise ValueError(f"Unknown provider: {provider}")
