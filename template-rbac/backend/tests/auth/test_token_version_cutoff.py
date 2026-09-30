"""The database cut-off for "sign out everywhere" (#195).

`users.token_version` is bumped by change-password, password reset and
logout-all in the same transaction as their other changes. Access
tokens carry the version they were issued under (`ver`) and
`get_current_user` rejects any token whose version differs from the
user's current one. That works without Redis, so these tests break
every Redis blocklist write and check the cut-off still holds.

Also covers the two refresh refusals (invalid client, absolute
timeout): with the family block failing they return the normal 401.
"""

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from kalekit.auth.repository import (
    create_password_reset_token,
    find_user_by_email,
    get_refresh_token_by_hash,
)
from kalekit.auth.service import (
    generate_verification_token,
    hash_refresh_token,
    hash_verification_token,
    password_reset_token_expiry,
)
from kalekit.config import settings
from tests.auth.test_redis_revocation_guards import (
    _break_blocklist_writes,
    _login,
    _refresh_status,
)

_OLD = "old-password123"
_NEW = "new-password456"


async def _me_status(client: AsyncClient, auth_header, token: str) -> int:
    response = await client.get("/v1/auth/me", headers=auth_header(token))
    return response.status_code


# --- Refresh refusals with Redis down ------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_invalid_client_returns_401_when_the_family_block_fails(
    client: AsyncClient,
    register,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await register("refresh-bad-client@example.com", _OLD)
    tokens = await _login(client, "refresh-bad-client@example.com", _OLD)
    row = await get_refresh_token_by_hash(
        session, hash_refresh_token(tokens["refresh_token"])
    )
    assert row is not None
    row.client = "not-a-client"
    await session.flush()

    await _break_blocklist_writes(monkeypatch)
    with capture_logs() as logs:
        response = await client.post(
            "/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Refresh token invalid"}
    assert any(log["event"] == "refresh_family_block_failed" for log in logs)


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_absolute_timeout_returns_401_when_the_family_block_fails(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    await register("refresh-abs-timeout@example.com", _OLD)
    tokens = await _login(client, "refresh-abs-timeout@example.com", _OLD)
    monkeypatch.setattr(
        type(settings), "session_absolute_timeout", lambda self, client: timedelta(0)
    )

    await _break_blocklist_writes(monkeypatch)
    with capture_logs() as logs:
        response = await client.post(
            "/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Session expired"}
    assert any(log["event"] == "refresh_family_block_failed" for log in logs)


# --- Cut-off without Redis -----------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_all_cuts_off_other_access_tokens_with_redis_down(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    await register("cutoff-logout-all@example.com", _OLD)
    first = await _login(client, "cutoff-logout-all@example.com", _OLD)
    second = await _login(client, "cutoff-logout-all@example.com", _OLD)

    await _break_blocklist_writes(monkeypatch)
    with capture_logs() as logs:
        response = await client.post(
            "/v1/auth/logout-all", headers=auth_header(first["access_token"])
        )

    assert response.status_code == 204
    assert any(log["event"] == "logout_all_block_failed" for log in logs)
    assert await _me_status(client, auth_header, first["access_token"]) == 401
    assert await _me_status(client, auth_header, second["access_token"]) == 401
    assert await _refresh_status(client, second["refresh_token"]) == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_cuts_off_other_access_tokens_with_redis_down(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    await register("cutoff-change-pw@example.com", _OLD)
    current = await _login(client, "cutoff-change-pw@example.com", _OLD)
    other = await _login(client, "cutoff-change-pw@example.com", _OLD)

    await _break_blocklist_writes(monkeypatch)
    with capture_logs() as logs:
        response = await client.post(
            "/v1/auth/change-password",
            headers=auth_header(current["access_token"]),
            json={"current_password": _OLD, "new_password": _NEW},
        )

    assert response.status_code == 200
    assert response.json() == {"detail": "Password changed"}
    assert any(log["event"] == "change_password_block_failed" for log in logs)
    assert await _me_status(client, auth_header, other["access_token"]) == 401
    assert await _refresh_status(client, other["refresh_token"]) == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_password_reset_cuts_off_access_tokens_with_redis_down(
    client: AsyncClient,
    register,
    auth_header,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "cutoff-reset@example.com"
    await register(email, _OLD)
    victim = await _login(client, email, _OLD)
    user = await find_user_by_email(session, email)
    assert user is not None
    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )

    await _break_blocklist_writes(monkeypatch)
    with capture_logs() as logs:
        response = await client.post(
            "/v1/auth/password/reset",
            json={"token": raw_token, "new_password": _NEW},
        )

    assert response.status_code == 200
    assert response.json() == {"detail": "Password reset"}
    assert any(log["event"] == "password_reset_block_failed" for log in logs)
    assert await _me_status(client, auth_header, victim["access_token"]) == 401


# --- The change-password caller keeps working ---------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_caller_refreshes_into_a_working_access_token(
    client: AsyncClient, register, auth_header
) -> None:
    await register("cutoff-caller@example.com", _OLD)
    caller = await _login(client, "cutoff-caller@example.com", _OLD)

    response = await client.post(
        "/v1/auth/change-password",
        headers=auth_header(caller["access_token"]),
        json={"current_password": _OLD, "new_password": _NEW},
    )
    assert response.status_code == 200

    # The caller's own access token is cut off too...
    assert await _me_status(client, auth_header, caller["access_token"]) == 401
    # ...but its session survives: refresh yields a token that passes.
    refreshed = await client.post(
        "/v1/auth/refresh", json={"refresh_token": caller["refresh_token"]}
    )
    assert refreshed.status_code == 200
    assert (
        await _me_status(client, auth_header, refreshed.json()["access_token"]) == 200
    )


# --- Same-second edge ----------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_same_second_tokens_before_and_after_the_change_are_told_apart(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The version is a counter, not a timestamp, so no clock resolution
    is involved: a token issued right before the change is rejected and
    one issued right after is accepted, however close together they are.

    The clock used for token issuance is frozen so every token below gets
    the same `exp`, i.e. all are issued in the same second. Redis writes
    are broken so the `ver` check alone decides the outcome, not the
    Redis session block."""
    import jwt

    from kalekit.auth import service

    frozen = datetime.now(timezone.utc)

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return frozen

    monkeypatch.setattr(service, "datetime", _FrozenDatetime)

    email = "cutoff-same-second@example.com"
    await register(email, _OLD)
    before = await _login(client, email, _OLD)
    actor = await _login(client, email, _OLD)

    await _break_blocklist_writes(monkeypatch)
    changed = await client.post(
        "/v1/auth/change-password",
        headers=auth_header(actor["access_token"]),
        json={"current_password": _OLD, "new_password": _NEW},
    )
    assert changed.status_code == 200
    after = await _login(client, email, _NEW)

    def _exp(token: str) -> int:
        return jwt.decode(token, options={"verify_signature": False})["exp"]

    assert _exp(before["access_token"]) == _exp(after["access_token"])
    assert await _me_status(client, auth_header, before["access_token"]) == 401
    assert await _me_status(client, auth_header, after["access_token"]) == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_token_version_is_written_to_the_user_and_the_token_claim(
    client: AsyncClient, register, auth_header, session: AsyncSession
) -> None:
    import jwt

    email = "cutoff-claim@example.com"
    await register(email, _OLD)
    tokens = await _login(client, email, _OLD)
    user = await find_user_by_email(session, email)
    assert user is not None
    assert user.token_version == 0
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    assert claims["ver"] == 0

    await client.post(
        "/v1/auth/logout-all", headers=auth_header(tokens["access_token"])
    )
    await session.refresh(user)
    assert user.token_version == 1
