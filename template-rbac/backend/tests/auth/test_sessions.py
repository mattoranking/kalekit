from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.models.refresh_token import RefreshToken


async def _login_pair(
    client: AsyncClient, email: str, user_agent: str | None = None
) -> tuple[str, str]:
    """Register + login, returning (access_token, refresh_token)."""
    await client.post(
        "/v1/auth/register",
        json={"email": email, "password": "password123"},
    )
    headers = {"User-Agent": user_agent} if user_agent else {}
    response = await client.post(
        "/v1/auth/login",
        json={"email": email, "password": "password123"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio(loop_scope="session")
async def test_list_sessions_records_device_and_marks_current(
    client: AsyncClient,
) -> None:
    access_token, _ = await _login_pair(
        client, "sessions-one@example.com", user_agent="TestAgent/1.0"
    )

    response = await client.get("/v1/auth/sessions", headers=_auth(access_token))

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    session = items[0]
    assert session["device_info"] == "TestAgent/1.0"
    assert session["is_current"] is True
    assert session["created_at"]
    assert session["last_used_at"]


@pytest.mark.asyncio(loop_scope="session")
async def test_list_sessions_shows_one_entry_per_session(
    client: AsyncClient,
) -> None:
    email = "sessions-two@example.com"
    access_token_a, _ = await _login_pair(client, email, user_agent="DeviceA")
    _, _ = await _login_pair(client, email, user_agent="DeviceB")

    response = await client.get("/v1/auth/sessions", headers=_auth(access_token_a))

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 2
    device_infos = {item["device_info"] for item in items}
    assert device_infos == {"DeviceA", "DeviceB"}
    # Only the session behind the token used for this request is current.
    current = [item for item in items if item["is_current"]]
    assert len(current) == 1
    assert current[0]["device_info"] == "DeviceA"


@pytest.mark.asyncio(loop_scope="session")
async def test_list_sessions_only_shows_the_callers_own_sessions(
    client: AsyncClient,
) -> None:
    access_token_a, _ = await _login_pair(client, "sessions-owner-a@example.com")
    await _login_pair(client, "sessions-owner-b@example.com")

    response = await client.get("/v1/auth/sessions", headers=_auth(access_token_a))

    assert response.status_code == 200
    assert len(response.json()["items"]) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_revoke_session_prevents_further_refresh(
    client: AsyncClient,
) -> None:
    access_token, refresh_token = await _login_pair(
        client, "sessions-revoke@example.com"
    )

    sessions = await client.get("/v1/auth/sessions", headers=_auth(access_token))
    session_id = sessions.json()["items"][0]["id"]

    delete_response = await client.delete(
        f"/v1/auth/sessions/{session_id}", headers=_auth(access_token)
    )
    assert delete_response.status_code == 204

    refresh_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_revoke_session_blocks_its_live_access_token_immediately(
    client: AsyncClient,
) -> None:
    """Without this, the access token minted for the revoked session
    would keep working for the rest of its natural lifetime -- the
    session wouldn't actually be over."""
    access_token, _ = await _login_pair(client, "sessions-block@example.com")

    sessions = await client.get("/v1/auth/sessions", headers=_auth(access_token))
    session_id = sessions.json()["items"][0]["id"]

    ok = await client.get("/v1/auth/me", headers=_auth(access_token))
    assert ok.status_code == 200

    await client.delete(f"/v1/auth/sessions/{session_id}", headers=_auth(access_token))

    blocked = await client.get("/v1/auth/me", headers=_auth(access_token))
    assert blocked.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_cannot_revoke_another_users_session(client: AsyncClient) -> None:
    access_token_a, _ = await _login_pair(client, "sessions-victim@example.com")
    access_token_b, _ = await _login_pair(client, "sessions-attacker@example.com")

    sessions = await client.get("/v1/auth/sessions", headers=_auth(access_token_a))
    victim_session_id = sessions.json()["items"][0]["id"]

    response = await client.delete(
        f"/v1/auth/sessions/{victim_session_id}", headers=_auth(access_token_b)
    )
    assert response.status_code == 404

    # The victim's session must still be alive/unaffected.
    still_there = await client.get("/v1/auth/sessions", headers=_auth(access_token_a))
    assert len(still_there.json()["items"]) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_expired_but_unrevoked_session_is_not_listed(
    client: AsyncClient, session: AsyncSession
) -> None:
    """A refresh token that expired naturally (never explicitly
    revoked) shouldn't show up as an active session -- the user can't
    actually do anything with it, so listing it would be misleading."""
    email = "sessions-expired@example.com"
    access_token, _ = await _login_pair(client, email)

    user = await find_user_by_email(session, email)
    assert user is not None
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.user_id == user.id)
    )
    token_row = result.scalar_one()
    token_row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    await session.flush()

    response = await client.get("/v1/auth/sessions", headers=_auth(access_token))

    assert response.status_code == 200
    assert response.json()["items"] == []


@pytest.mark.asyncio(loop_scope="session")
async def test_revoke_unknown_session_returns_404(client: AsyncClient) -> None:
    access_token, _ = await _login_pair(client, "sessions-unknown@example.com")

    response = await client.delete(
        "/v1/auth/sessions/00000000-0000-0000-0000-000000000000",
        headers=_auth(access_token),
    )
    assert response.status_code == 404
