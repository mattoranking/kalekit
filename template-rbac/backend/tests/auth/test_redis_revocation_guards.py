"""Redis outage behaviour for the four session-revoking endpoints #108
left unguarded (#177): logout-all, DELETE /sessions/{id}, change-password
and password reset.

When the blocklist write fails each returns the same clean 503 as
logout, never a 500 and never a success. The database changes made
before the failed block are COMMITTED, not rolled back:

* the refresh tokens stay revoked, so the sessions cannot mint new
  access tokens; only access tokens already issued live on, for at most
  their natural lifetime;
* on change-password and reset the new password stays in force, so an
  attacker holding the old password or the reset-triggering session is
  locked out.

Rolling back would leave the old password and every refresh token alive
for as long as Redis is down.
"""

from typing import Any

import pytest
import redis.exceptions
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import get_redis
from kalekit.auth.repository import (
    create_password_reset_token,
    find_user_by_email,
)
from kalekit.auth.service import (
    generate_verification_token,
    hash_verification_token,
    password_reset_token_expiry,
)
from kalekit.models.password_reset_token import PasswordResetToken

_OLD = "old-password123"
_NEW = "new-password456"
_DETAIL = {"detail": "Could not complete sign-out, please try again"}


def _outage() -> redis.exceptions.ConnectionError:
    return redis.exceptions.ConnectionError("simulated redis outage")


class _FlakyRedis:
    """The real Redis, except SET and pipelines raise ConnectionError.

    The blocklist read in get_current_user still works, so the request
    reaches the handler and fails at the block step.
    """

    def __init__(self, real: Any) -> None:
        self._real = real

    async def set(self, *args: object, **kwargs: object) -> None:
        raise _outage()

    def pipeline(self, *args: object, **kwargs: object) -> None:
        raise _outage()

    def __getattr__(self, name: str):
        return getattr(self._real, name)


async def _break_blocklist_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    real = await get_redis()

    async def _flaky_get_redis() -> _FlakyRedis:
        return _FlakyRedis(real)

    monkeypatch.setattr("kalekit.auth.permissions.get_redis", _flaky_get_redis)


async def _login(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _refresh_status(client: AsyncClient, refresh_token: str) -> int:
    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    return response.status_code


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_all_returns_503_and_keeps_the_refresh_revocation(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    email = "logout-all-outage@example.com"
    await register(email, _OLD)
    first = await _login(client, email, _OLD)
    second = await _login(client, email, _OLD)

    with monkeypatch.context() as m:
        await _break_blocklist_writes(m)
        response = await client.post(
            "/v1/auth/logout-all", headers=auth_header(first["access_token"])
        )

    assert response.status_code == 503
    assert response.json() == _DETAIL
    # The revocation committed: neither session can refresh.
    assert await _refresh_status(client, first["refresh_token"]) == 401
    assert await _refresh_status(client, second["refresh_token"]) == 401

    # A retry with Redis back finishes the job.
    retry = await client.post(
        "/v1/auth/logout-all", headers=auth_header(first["access_token"])
    )
    assert retry.status_code == 204
    me = await client.get("/v1/auth/me", headers=auth_header(second["access_token"]))
    assert me.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_revoke_session_returns_503_and_keeps_the_refresh_revocation(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    email = "revoke-session-outage@example.com"
    await register(email, _OLD)
    current = await _login(client, email, _OLD)
    other = await _login(client, email, _OLD)
    listing = await client.get(
        "/v1/auth/sessions", headers=auth_header(current["access_token"])
    )
    other_id = next(s["id"] for s in listing.json()["items"] if not s["is_current"])

    with monkeypatch.context() as m:
        await _break_blocklist_writes(m)
        response = await client.delete(
            f"/v1/auth/sessions/{other_id}",
            headers=auth_header(current["access_token"]),
        )

    assert response.status_code == 503
    assert response.json() == _DETAIL
    assert await _refresh_status(client, other["refresh_token"]) == 401

    retry = await client.delete(
        f"/v1/auth/sessions/{other_id}", headers=auth_header(current["access_token"])
    )
    assert retry.status_code == 204
    me = await client.get("/v1/auth/me", headers=auth_header(other["access_token"]))
    assert me.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_returns_503_and_keeps_the_change_and_revocation(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    email = "change-pw-outage@example.com"
    await register(email, _OLD)
    current = await _login(client, email, _OLD)
    other = await _login(client, email, _OLD)

    with monkeypatch.context() as m:
        await _break_blocklist_writes(m)
        response = await client.post(
            "/v1/auth/change-password",
            headers=auth_header(current["access_token"]),
            json={"current_password": _OLD, "new_password": _NEW},
        )

    assert response.status_code == 503
    assert response.json() == _DETAIL
    # The new password is in force and the old one is dead...
    bad = await client.post("/v1/auth/login", json={"email": email, "password": _OLD})
    assert bad.status_code == 401
    await _login(client, email, _NEW)
    # ...and the other session's refresh token stays revoked.
    assert await _refresh_status(client, other["refresh_token"]) == 401
    # The caller's own session is spared, as on the success path.
    assert await _refresh_status(client, current["refresh_token"]) == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_password_reset_returns_503_and_keeps_the_reset_and_revocation(
    client: AsyncClient,
    register,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "reset-outage@example.com"
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

    with monkeypatch.context() as m:
        await _break_blocklist_writes(m)
        response = await client.post(
            "/v1/auth/password/reset",
            json={"token": raw_token, "new_password": _NEW},
        )

    assert response.status_code == 503
    assert response.json() == _DETAIL
    bad = await client.post("/v1/auth/login", json={"email": email, "password": _OLD})
    assert bad.status_code == 401
    await _login(client, email, _NEW)
    assert await _refresh_status(client, victim["refresh_token"]) == 401
    # The single-use token was consumed with the commit.
    row = (
        await session.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == hash_verification_token(raw_token)
            )
        )
    ).scalar_one()
    await session.refresh(row)
    assert row.used_at is not None
