"""Redis outage behaviour for logout and logout-all (#122).

The access-token blocklist lives only in Redis, so when the write fails
both endpoints fail CLOSED with a clean 503 (same direction as RBAC
#108). The 503 is returned, not raised: get_db_session rolls back on any
exception, which would undo the database revoke that ran just before.
"""

from collections.abc import AsyncGenerator
from typing import Any

import pytest
import redis.exceptions
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.blocklist import get_redis
from kalekit.postgres import get_db_session

_PASSWORD = "correct-password"
_DETAIL = {"detail": "Could not complete sign-out, please try again"}


class _FlakyRedis:
    """The real Redis, except `set` raises ConnectionError."""

    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str):
        if name == "set":

            async def _fail(*args: object, **kwargs: object) -> None:
                raise redis.exceptions.ConnectionError("simulated redis outage")

            return _fail
        return getattr(self._real, name)


async def _break_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    real = await get_redis()

    async def _flaky_get_redis() -> _FlakyRedis:
        return _FlakyRedis(real)

    # Only the write fails: the blocklist read in get_current_user
    # still works, so the request reaches the handler itself.
    monkeypatch.setattr("kalekit.auth.blocklist.get_redis", _flaky_get_redis)


async def _login_pair(client: AsyncClient, register, email: str) -> tuple[str, str]:
    await register(email, _PASSWORD)
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": _PASSWORD}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_returns_503_when_the_blocklist_write_fails(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    access, refresh = await _login_pair(client, register, "logout-outage@example.com")

    await _break_redis(monkeypatch)
    response = await client.post(
        "/v1/auth/logout",
        json={"refresh_token": refresh},
        headers=auth_header(access),
    )

    assert response.status_code == 503
    assert response.json() == _DETAIL
    # The database revoke ran before the failure: the family is dead.
    monkeypatch.undo()
    reuse = await client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    assert reuse.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_can_be_retried_once_redis_is_back(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    access, refresh = await _login_pair(client, register, "logout-retry@example.com")

    with monkeypatch.context() as m:
        await _break_redis(m)
        failed = await client.post(
            "/v1/auth/logout",
            json={"refresh_token": refresh},
            headers=auth_header(access),
        )
    assert failed.status_code == 503

    retry = await client.post(
        "/v1/auth/logout",
        json={"refresh_token": refresh},
        headers=auth_header(access),
    )
    assert retry.status_code == 204
    revoked = await client.get("/v1/auth/me", headers=auth_header(access))
    assert revoked.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_all_returns_503_when_the_blocklist_write_fails(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    access, refresh = await _login_pair(
        client, register, "logoutall-outage@example.com"
    )

    await _break_redis(monkeypatch)
    response = await client.post("/v1/auth/logout-all", headers=auth_header(access))

    assert response.status_code == 503
    assert response.json() == _DETAIL
    monkeypatch.undo()
    reuse = await client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    assert reuse.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_all_can_be_retried_once_redis_is_back(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    access, _ = await _login_pair(client, register, "logoutall-retry@example.com")

    with monkeypatch.context() as m:
        await _break_redis(m)
        failed = await client.post("/v1/auth/logout-all", headers=auth_header(access))
    assert failed.status_code == 503

    retry = await client.post("/v1/auth/logout-all", headers=auth_header(access))
    assert retry.status_code == 204
    revoked = await client.get("/v1/auth/me", headers=auth_header(access))
    assert revoked.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("path", ["/v1/auth/logout", "/v1/auth/logout-all"])
async def test_the_503_lets_the_database_session_commit(
    path: str,
    client: AsyncClient,
    session: AsyncSession,
    register,
    auth_header,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client fixture's session override never commits or rolls back,
    so it cannot tell a returned 503 from a raised one. Mirror the real
    get_db_session's control flow (commit on normal exit, rollback on an
    exception) and record which happened."""
    access, refresh = await _login_pair(
        client, register, f"commit-{path.rsplit('/', 1)[1]}@example.com"
    )
    events: list[str] = []

    async def _recording_db_session() -> AsyncGenerator[AsyncSession]:
        try:
            yield session
        except Exception:
            events.append("rollback")
            raise
        else:
            events.append("commit")

    app: FastAPI = client._transport.app  # type: ignore[attr-defined]
    app.dependency_overrides[get_db_session] = _recording_db_session
    await _break_redis(monkeypatch)
    response = await client.post(
        path, json={"refresh_token": refresh}, headers=auth_header(access)
    )

    assert response.status_code == 503
    assert events == ["commit"]
