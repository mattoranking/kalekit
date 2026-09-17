"""Sliding session expiration (see #6): every refresh resets a
session's *idle* deadline, but its *absolute* deadline -- measured from
the original login -- never moves. Idle and absolute timeouts are
configured per client (web/mobile/admin)."""

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.config import settings
from kalekit.models.refresh_token import RefreshToken


async def _login_pair(
    client: AsyncClient, email: str, client_type: str = "web"
) -> tuple[str, str]:
    """Register + login as `client_type`, returning
    (access_token, refresh_token)."""
    await client.post(
        "/v1/auth/register",
        json={"email": email, "password": "password123"},
    )
    response = await client.post(
        "/v1/auth/login",
        json={"email": email, "password": "password123", "client": client_type},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


async def _only_token_row(session: AsyncSession, email: str) -> RefreshToken:
    user = await find_user_by_email(session, email)
    assert user is not None
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.user_id == user.id)
    )
    return result.scalar_one()


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_resets_idle_expiry_but_not_absolute_session_start(
    client: AsyncClient, session: AsyncSession
) -> None:
    email = "sliding-rotate@example.com"
    _, refresh_token = await _login_pair(client, email)

    original = await _only_token_row(session, email)
    original_family_created_at = original.family_created_at

    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200

    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.family_id == original.family_id,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    rotated = result.scalar_one()

    # The idle deadline moved forward (a fresh idle window)...
    assert rotated.expires_at > original.expires_at
    # ...but the session's absolute start is carried through unchanged.
    assert rotated.family_created_at == original_family_created_at
    # ...and so is which client the session belongs to.
    assert rotated.client == original.client == "web"


@pytest.mark.asyncio(loop_scope="session")
async def test_idle_session_is_rejected_after_its_idle_timeout(
    client: AsyncClient, session: AsyncSession
) -> None:
    email = "idle-expired@example.com"
    _, refresh_token = await _login_pair(client, email, client_type="admin")

    token_row = await _only_token_row(session, email)
    # Simulate the admin idle timeout (30 minutes by default) having
    # already elapsed without a refresh.
    token_row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await session.flush()

    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_session_is_rejected_after_its_absolute_timeout_even_if_active(
    client: AsyncClient, session: AsyncSession
) -> None:
    """An admin session that has been refreshed regularly (so its idle
    deadline is nowhere near expiring) must still be forced to end once
    its absolute timeout (12 hours by default, from the original login)
    has passed."""
    email = "admin-absolute-timeout@example.com"
    _, refresh_token = await _login_pair(client, email, client_type="admin")

    token_row = await _only_token_row(session, email)
    # The session "started" 13 hours ago -- past the 12-hour default
    # absolute timeout -- even though its idle expiry (30 min out from
    # *now*, not from family_created_at) is nowhere close to lapsing.
    token_row.family_created_at = datetime.now(timezone.utc) - timedelta(hours=13)
    await session.flush()

    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert response.status_code == 401

    # The whole family is revoked, not just this one request rejected --
    # the session is over.
    replay = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert replay.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_absolute_timeout_is_configurable(
    client: AsyncClient, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "SESSION_ABSOLUTE_TIMEOUT_HOURS_ADMIN", 1)

    email = "admin-configurable-timeout@example.com"
    _, refresh_token = await _login_pair(client, email, client_type="admin")

    token_row = await _only_token_row(session, email)
    token_row.family_created_at = datetime.now(timezone.utc) - timedelta(minutes=61)
    await session.flush()

    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("client_type", ["web", "mobile"])
async def test_web_session_used_regularly_stays_valid_past_the_old_7_day_limit(
    client: AsyncClient, session: AsyncSession, client_type: str
) -> None:
    """Before #6, every refresh token expired 7 days after it was
    issued (REFRESH_TOKEN_EXPIRE_DAYS), full stop. Web/mobile now have
    no absolute timeout at all -- only a sliding idle timeout -- so a
    session that started well over 7 days ago must still refresh fine
    as long as it hasn't gone idle. Parametrized over both consumer
    clients since they're distinct code paths in config and token
    stamping despite sharing the same policy defaults."""
    email = f"{client_type}-outlives-old-limit@example.com"
    _, refresh_token = await _login_pair(client, email, client_type=client_type)

    token_row = await _only_token_row(session, email)
    # The session "started" 30 days ago -- long past the old flat
    # 7-day cutoff -- but its idle expiry (90 days out) is untouched.
    token_row.family_created_at = datetime.now(timezone.utc) - timedelta(days=30)
    await session.flush()

    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_new_login_starts_a_fresh_family_created_at(
    client: AsyncClient, session: AsyncSession
) -> None:
    email = "fresh-family-created-at@example.com"
    before = datetime.now(timezone.utc)
    await _login_pair(client, email)
    after = datetime.now(timezone.utc)

    token_row = await _only_token_row(session, email)

    assert before <= token_row.family_created_at <= after
