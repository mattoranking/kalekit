"""Tests for step-up re-authentication (#16): POST /auth/reauthenticate
and the require_recent_auth dependency it feeds, applied to
change-password and session revocation."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import (
    consume_oauth_reauth_ticket,
    store_oauth_reauth_ticket,
)
from kalekit.auth.repository import find_user_by_email
from kalekit.config import settings
from kalekit.models.refresh_token import RefreshToken
from kalekit.oauth.client import OAUTH_PROVIDERS


async def _login_pair(
    client: AsyncClient, email: str, password: str = "password12345"
) -> tuple[str, str]:
    """Register + login, returning (access_token, refresh_token)."""
    await client.post(
        "/v1/auth/register",
        json={"email": email, "password": password},
    )
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _age_current_session(
    session: AsyncSession, email: str, minutes: int
) -> None:
    """Push the caller's (only) active session's auth_time into the
    past, simulating a session that's been alive/refreshed for a while
    without a fresh credential check."""
    user = await find_user_by_email(session, email)
    assert user is not None
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.user_id == user.id)
    )
    rows = result.scalars().all()
    assert rows, "expected an active session row"
    for row in rows:
        row.auth_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    await session.flush()


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_succeeds_within_the_reauth_window(
    client: AsyncClient,
) -> None:
    access_token, _ = await _login_pair(client, "reauth-cp-fresh@example.com")

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "password12345", "new_password": "newpassword456"},
    )

    assert response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_fails_with_reauth_required_once_stale(
    client: AsyncClient, session: AsyncSession
) -> None:
    email = "reauth-cp-stale@example.com"
    access_token, _ = await _login_pair(client, email)
    await _age_current_session(session, email, minutes=11)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "password12345", "new_password": "newpassword456"},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "reauth_required"


@pytest.mark.asyncio(loop_scope="session")
async def test_revoke_session_fails_with_reauth_required_once_stale(
    client: AsyncClient, session: AsyncSession
) -> None:
    email = "reauth-revoke-stale@example.com"
    access_token, _ = await _login_pair(client, email)
    sessions = await client.get("/v1/auth/sessions", headers=_auth(access_token))
    session_id = sessions.json()["items"][0]["id"]

    await _age_current_session(session, email, minutes=11)

    response = await client.delete(
        f"/v1/auth/sessions/{session_id}", headers=_auth(access_token)
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "reauth_required"


@pytest.mark.asyncio(loop_scope="session")
async def test_reauthenticate_with_wrong_password_fails(
    client: AsyncClient,
) -> None:
    access_token, _ = await _login_pair(client, "reauth-wrong-pw@example.com")

    response = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"password": "not-it"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_reauthenticate_restores_access_to_gated_action(
    client: AsyncClient, session: AsyncSession
) -> None:
    email = "reauth-restore@example.com"
    access_token, _ = await _login_pair(client, email)
    await _age_current_session(session, email, minutes=11)

    # Gated action fails while stale.
    stale = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "password12345", "new_password": "irrelevant-1234"},
    )
    assert stale.status_code == 403

    reauth = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"password": "password12345"},
    )
    assert reauth.status_code == 200

    # Same access token, no new tokens issued -- the gated action now
    # succeeds because the session's auth_time was advanced in place.
    fresh = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "password12345", "new_password": "newpassword789"},
    )
    assert fresh.status_code == 200, fresh.text


@pytest.mark.asyncio(loop_scope="session")
async def test_reauthenticate_requires_oauth_ticket_for_oauth_only_user(
    client: AsyncClient, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OAuth-only user (no password_hash) can't satisfy
    /auth/reauthenticate with a password at all."""
    access_token = await _oauth_only_login(
        client,
        session,
        monkeypatch,
        "oauth-only-reauth@example.com",
        provider_id=42424242,
    )

    no_ticket = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={},
    )
    assert no_ticket.status_code == 400

    bad_ticket = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"oauth_ticket": "not-a-real-ticket"},
    )
    assert bad_ticket.status_code == 401


async def _oauth_only_login(
    client: AsyncClient,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    email: str,
    provider_id: int,
) -> str:
    """Log an OAuth-only user in via the real /oauth flow (mocked
    provider, same as test_endpoints.py's _mock_provider), returning
    their access token. This user has no password_hash at all."""
    github = OAUTH_PROVIDERS["github"]

    async def fake_exchange_code(code: str, code_verifier: str | None = None) -> dict:
        return {"access_token": "provider-access-token"}

    async def fake_get_user_info(access_token: str) -> dict:
        return {"id": provider_id, "email": email}

    async def fake_email_verified(*args: Any, **kwargs: Any) -> bool:
        return True

    monkeypatch.setattr(github, "exchange_code", fake_exchange_code)
    monkeypatch.setattr(github, "get_user_info", fake_get_user_info)
    monkeypatch.setattr(
        "kalekit.oauth.endpoints._get_provider_email_verified", fake_email_verified
    )

    authorize = await client.get("/v1/oauth/github/authorize")
    assert authorize.status_code == 200
    state = parse_qs(urlsplit(authorize.json()["authorization_url"]).query)["state"][0]

    callback = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )
    assert callback.status_code == 302
    exchange_code = parse_qs(urlsplit(callback.headers["location"]).query)["code"][0]

    exchanged = await client.post("/v1/oauth/exchange", json={"code": exchange_code})
    assert exchanged.status_code == 200

    user = await find_user_by_email(session, email)
    assert user is not None
    assert user.password_hash is None

    return exchanged.json()["access_token"]


@pytest.mark.asyncio(loop_scope="session")
async def test_reauthenticate_succeeds_with_a_valid_oauth_ticket(
    client: AsyncClient, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    email = "reauth-oauth-ticket@example.com"
    access_token = await _oauth_only_login(
        client, session, monkeypatch, email, provider_id=555555
    )
    await _age_current_session(session, email, minutes=11)

    user = await find_user_by_email(session, email)
    assert user is not None

    # Simulate a completed `reauth=true` OAuth callback (the full HTTP
    # round trip is covered separately by
    # test_oauth_reauth_callback_mints_ticket_not_a_session below) by
    # minting a ticket the same way oauth_callback does.
    ticket = "test-ticket-" + uuid.uuid4().hex
    await store_oauth_reauth_ticket(ticket, str(user.id), ttl_seconds=60)

    response = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"oauth_ticket": ticket},
    )

    assert response.status_code == 200

    # Single-use: a second attempt with the same ticket fails.
    assert await consume_oauth_reauth_ticket(ticket) is None


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_reauth_callback_mints_ticket_not_a_session(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `reauth=true` authorize->callback round trip must hand back a
    `reauth_ticket`, not a fresh login `code` -- it must not be usable
    to mint a whole new token pair by itself."""
    github = OAUTH_PROVIDERS["github"]

    async def fake_exchange_code(code: str, code_verifier: str | None = None) -> dict:
        return {"access_token": "provider-access-token"}

    async def fake_get_user_info(access_token: str) -> dict:
        return {"id": 7777, "email": "reauth-flow@example.com"}

    async def fake_email_verified(*args: Any, **kwargs: Any) -> bool:
        return True

    monkeypatch.setattr(github, "exchange_code", fake_exchange_code)
    monkeypatch.setattr(github, "get_user_info", fake_get_user_info)
    monkeypatch.setattr(
        "kalekit.oauth.endpoints._get_provider_email_verified", fake_email_verified
    )

    authorize = await client.get(
        "/v1/oauth/github/authorize", params={"reauth": "true"}
    )
    assert authorize.status_code == 200
    state = parse_qs(
        urlsplit(authorize.json()["authorization_url"]).query
    )["state"][0]

    callback = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )

    assert callback.status_code == 302
    location = callback.headers["location"]
    query = parse_qs(urlsplit(location).query)
    assert list(query.keys()) == ["reauth_ticket"]
    assert "access_token" not in location
    assert "refresh_token" not in location


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_reauth_callback_puts_ticket_before_fragment(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """redirect_to may carry a client-side URL fragment (#...). The
    reauth_ticket query param must land as a real query param *before*
    the fragment, not inside/after it where the frontend router may
    never see it."""
    github = OAUTH_PROVIDERS["github"]

    async def fake_exchange_code(code: str, code_verifier: str | None = None) -> dict:
        return {"access_token": "provider-access-token"}

    async def fake_get_user_info(access_token: str) -> dict:
        return {"id": 7778, "email": "reauth-fragment@example.com"}

    async def fake_email_verified(*args: Any, **kwargs: Any) -> bool:
        return True

    monkeypatch.setattr(github, "exchange_code", fake_exchange_code)
    monkeypatch.setattr(github, "get_user_info", fake_get_user_info)
    monkeypatch.setattr(
        "kalekit.oauth.endpoints._get_provider_email_verified", fake_email_verified
    )

    redirect_to = f"{settings.FRONTEND_URL}/account#security"
    authorize = await client.get(
        "/v1/oauth/github/authorize",
        params={"reauth": "true", "redirect_to": redirect_to},
    )
    assert authorize.status_code == 200
    state = parse_qs(
        urlsplit(authorize.json()["authorization_url"]).query
    )["state"][0]

    callback = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )

    assert callback.status_code == 302
    location = callback.headers["location"]
    parts = urlsplit(location)

    # The fragment is preserved as-is, at the end of the URL.
    assert parts.fragment == "security"
    # The ticket is a real query param, not swallowed into/after the
    # fragment.
    query = parse_qs(parts.query)
    assert list(query.keys()) == ["reauth_ticket"]
    # And it comes before the fragment in the raw string.
    assert location.index("reauth_ticket") < location.index("#security")


@pytest.mark.asyncio(loop_scope="session")
async def test_repeated_failed_reauth_attempts_are_rate_limited(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test: without this, an attacker holding a *stolen
    access token* (but not the account's password) could hit
    /auth/reauthenticate with unlimited password guesses to brute-force
    it and then legitimately step up the hijacked session -- defeating
    #16 entirely. Mirrors /auth/login's per-account rate-limit test."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "REAUTH_RATE_LIMIT_PER_ACCOUNT", 3)

    email = "reauth-bruteforced@example.com"
    access_token, _ = await _login_pair(client, email)

    for _ in range(3):
        response = await client.post(
            "/v1/auth/reauthenticate",
            headers=_auth(access_token),
            json={"password": "wrong-password"},
        )
        assert response.status_code == 401

    blocked = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"password": "wrong-password"},
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers

    # Even the *correct* password is blocked while the account is
    # rate-limited -- the whole point is to slow down guessing
    # regardless of whether the next guess happens to be right.
    still_blocked = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"password": "password12345"},
    )
    assert still_blocked.status_code == 429


@pytest.mark.asyncio(loop_scope="session")
async def test_a_successful_reauth_clears_the_account_failure_count(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "REAUTH_RATE_LIMIT_PER_ACCOUNT", 2)

    email = "reauth-recovers@example.com"
    access_token, _ = await _login_pair(client, email)

    # One failure, then a success -- should reset the counter rather
    # than leave it at 1/2.
    fail = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"password": "wrong-password"},
    )
    assert fail.status_code == 401

    success = await client.post(
        "/v1/auth/reauthenticate",
        headers=_auth(access_token),
        json={"password": "password12345"},
    )
    assert success.status_code == 200

    # Two more failures shouldn't be blocked yet -- if the counter
    # hadn't been cleared, this would already be the 3rd failure
    # against a limit of 2.
    for _ in range(2):
        response = await client.post(
            "/v1/auth/reauthenticate",
            headers=_auth(access_token),
            json={"password": "wrong-password"},
        )
        assert response.status_code == 401
