"""
OAuth2 authorization-code flow endpoints.

GET  /oauth/{provider}/authorize  → redirect URL + state
GET  /oauth/{provider}/callback   → exchange code, redirect to frontend
POST /oauth/exchange              → one-time code → JWT pair

State (and PKCE code_verifier for Twitter) are stored in Redis
with a short TTL to prevent CSRF and replay attacks.

The callback never puts tokens in the redirect URL: it mints a
short-lived, single-use exchange code, stashes the token pair in Redis
under it, and redirects the browser to the (allowlisted) frontend with
only that code in the query string. The frontend then calls
POST /oauth/exchange server-side (see #13, the BFF route handler) to
trade the code for the real token pair -- tokens never transit the
browser's address bar or history.
"""

import json
import secrets
from typing import Annotated
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.client_type import ClientType
from kalekit.auth.permissions import get_redis, get_scopes_for_roles
from kalekit.auth.repository import store_refresh_token
from kalekit.auth.schemas import TokenResponse
from kalekit.auth.service import (
    create_access_token,
    device_info_from_user_agent,
    generate_refresh_token,
    hash_refresh_token,
)
from kalekit.config import settings
from kalekit.oauth.client import OAUTH_PROVIDERS
from kalekit.oauth.repository import OAuthAccountLinkingError, find_or_create_oauth_user
from kalekit.postgres import get_db_session

router = APIRouter(prefix="/oauth", tags=["oauth"])

_STATE_TTL = 600  # 10 minutes


class OAuthExchangeRequest(BaseModel):
    code: str


def _get_provider(provider: str):
    client = OAUTH_PROVIDERS.get(provider)
    if not client:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
    return client


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _allowed_redirect_origins() -> set[str]:
    origins = {_origin(settings.FRONTEND_URL)}
    for raw in settings.OAUTH_REDIRECT_ALLOWLIST.split(","):
        raw = raw.strip()
        if raw:
            origins.add(_origin(raw))
    return origins


def _is_allowed_redirect(url: str) -> bool:
    """Only allow redirecting the browser to an origin we explicitly
    trust -- otherwise the callback is a textbook open redirect (an
    attacker crafts an authorize link with `redirect_to` pointing at
    their own site and rides the victim's login to it).
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    return _origin(url) in _allowed_redirect_origins()


@router.get("/{provider}/authorize")
async def oauth_authorize(
    provider: str,
    redirect_to: Annotated[str | None, Query()] = None,
    client_type: Annotated[ClientType, Query(alias="client")] = ClientType.web,
):
    """Generate an authorization URL and return it to the frontend.

    The frontend redirects the user's browser to this URL.
    State is stored in Redis so the callback can validate it.

    `redirect_to` is where the *callback* should send the user's
    browser after login completes -- validated against the allowlist
    now (fail fast) rather than only at callback time, and carried
    through Redis alongside the CSRF state.

    `client` is which app this OAuth sign-in is for (web/mobile/admin
    -- see #6); validated here (an unknown value 422s) and carried
    through Redis the same way `redirect_to` is, since the callback --
    not this endpoint -- is what actually mints the token pair.
    """
    provider_client = _get_provider(provider)
    state = secrets.token_urlsafe(32)

    target = redirect_to or settings.FRONTEND_URL
    if not _is_allowed_redirect(target):
        raise HTTPException(status_code=400, detail="Redirect target not allowed")

    authorization_url, code_verifier = provider_client.get_authorization_url(state)

    # Store state (and code_verifier for PKCE, the post-login redirect
    # target, and the requesting client) in Redis
    r = await get_redis()
    state_data = json.dumps(
        {
            "provider": provider,
            "code_verifier": code_verifier,
            "redirect_to": target,
            "client": client_type.value,
        }
    )
    await r.set(f"oauth_state:{state}", state_data, ex=_STATE_TTL)

    return {"authorization_url": authorization_url}


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: Annotated[str, Query()],
    state: Annotated[str, Query()],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Handle the OAuth provider's redirect.

    1. Validate state against Redis (prevents CSRF)
    2. Exchange the authorization code for an access token
    3. Fetch the user's profile from the provider
    4. Find or create a local User + OAuthAccount link
    5. Issue our own JWT pair, stash it behind a one-time exchange
       code, and redirect the browser back to the (allowlisted)
       frontend with only that code in the URL -- never the tokens
       themselves.
    """
    client = _get_provider(provider)

    # --- Validate state ---
    r = await get_redis()
    state_key = f"oauth_state:{state}"
    raw_state_data = await r.get(state_key)
    if not raw_state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    # Delete immediately — state is single-use
    await r.delete(state_key)

    state_data = json.loads(raw_state_data)
    stored_provider = state_data["provider"]
    code_verifier: str | None = state_data.get("code_verifier")
    redirect_to: str = state_data["redirect_to"]
    # `.get` with a "web" fallback so state minted by an authorize call
    # from just before this field existed (mid-deploy) still decodes
    # instead of KeyError-ing the callback.
    try:
        client_type = ClientType(state_data.get("client", ClientType.web.value))
    except ValueError:
        # Malformed callback state -- corrupted Redis data, a manual
        # edit, or a mid-deploy mismatch between an older /authorize
        # and a newer /callback -- rather than an unhandled ValueError
        # surfacing as a 500. 400, not 401: this isn't a session/token
        # being rejected, it's a bad callback request, same as the
        # provider/state mismatch check just below.
        raise HTTPException(status_code=400, detail="Invalid client in OAuth state")

    if stored_provider != provider:
        raise HTTPException(status_code=400, detail="State/provider mismatch")

    # Defense in depth: this was already validated in oauth_authorize
    # before being written to Redis, but Redis is server-controlled
    # data we trust here regardless -- re-checking is cheap and makes
    # the invariant explicit at the point it matters (the redirect).
    if not _is_allowed_redirect(redirect_to):
        raise HTTPException(status_code=400, detail="Redirect target not allowed")

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
    provider_email_verified = await _get_provider_email_verified(
        provider, user_info, provider_access_token, account_email
    )

    # --- Find or create local user ---
    try:
        user = await find_or_create_oauth_user(
            session,
            platform=provider,
            account_id=account_id,
            account_email=account_email,
            access_token=provider_access_token,
            refresh_token=provider_refresh_token,
            provider_email_verified=provider_email_verified,
        )
    except OAuthAccountLinkingError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    # --- Issue our token pair ---
    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    refresh_token, expires_at = generate_refresh_token(client_type)

    # Persist it like /auth/login does -- otherwise /auth/refresh (which
    # now validates against the DB) can never find this token and every
    # OAuth-issued refresh token would be permanently unusable. Also
    # capture device/IP the same way /auth/login does, so OAuth-created
    # sessions show up the same as password-login ones in
    # GET /auth/sessions, and stamp the family_id onto the access
    # token's `sid` claim so it's identifiable as "the current session"
    # there too.
    token_row = await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
        expires_at=expires_at,
        client=client_type,
        ip_address=request.client.host if request.client else None,
        device_info=device_info_from_user_agent(request.headers.get("user-agent")),
    )
    access_token = create_access_token(
        str(user.id),
        list(scopes),
        client=client_type,
        session_id=str(token_row.family_id),
    )

    # --- Hand off to the frontend without tokens in the URL ---
    # The token pair is stashed in Redis behind a single-use, short-lived
    # code; only that code goes in the redirect URL. The frontend's BFF
    # (see #13) exchanges it server-side via POST /oauth/exchange.
    exchange_code = secrets.token_urlsafe(32)
    await r.set(
        f"oauth_exchange:{exchange_code}",
        json.dumps(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
            }
        ),
        ex=settings.OAUTH_EXCHANGE_CODE_TTL_SECONDS,
    )

    separator = "&" if "?" in redirect_to else "?"
    return RedirectResponse(
        url=f"{redirect_to}{separator}{urlencode({'code': exchange_code})}",
        status_code=302,
    )


@router.post("/exchange", response_model=TokenResponse)
async def oauth_exchange(body: OAuthExchangeRequest):
    """Trade a one-time code (minted by /oauth/{provider}/callback) for
    the actual JWT pair. Meant to be called server-side by the
    frontend's BFF right after the post-login redirect -- the code is
    deleted on first use, so a leaked/replayed URL can't be exchanged
    twice.
    """
    r = await get_redis()
    exchange_key = f"oauth_exchange:{body.code}"
    raw = await r.get(exchange_key)
    if not raw:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    await r.delete(exchange_key)

    return TokenResponse(**json.loads(raw))


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


async def _get_provider_email_verified(
    provider: str,
    user_info: dict,
    access_token: str,
    account_email: str | None,
) -> bool:
    """Does the IdP itself vouch that `account_email` is verified?

    This is what find_or_create_oauth_user uses to decide whether it's
    safe to auto-link an OAuth sign-in to an existing password account
    (see the docstring there for the attack this guards against) --
    linking on an email the provider hasn't confirmed would just move
    the account-pre-hijack hole from "unverified" to "provider says
    so", so each provider is handled explicitly rather than assumed
    verified by default.
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
            e.get("email") == account_email and e.get("verified")
            for e in emails
        )

    # Twitter never returns an email in the first place, so
    # account_email is always None here already; any future provider
    # we haven't explicitly vetted defaults to unverified.
    return False
