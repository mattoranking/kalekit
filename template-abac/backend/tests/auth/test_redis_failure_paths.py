"""Redis outage behaviour for the access-token blocklist (port of RBAC #99).

Revocation state lives only in Redis, so when the blocklist can't be
read there is no way to tell a live token from a revoked one. The check
in `get_current_user` fails CLOSED with a 503; honouring the token would
keep stolen sessions alive for the length of the outage.
"""

import pytest
import redis.exceptions
from httpx import AsyncClient


class _DeadRedis:
    """Every command raises, like a Redis that has gone away."""

    def __getattr__(self, name: str):
        async def _fail(*args: object, **kwargs: object) -> None:
            raise redis.exceptions.ConnectionError("simulated redis outage")

        return _fail


async def _dead_get_redis() -> _DeadRedis:
    return _DeadRedis()


@pytest.mark.asyncio(loop_scope="session")
async def test_blocklist_redis_failure_returns_503_not_500(
    client: AsyncClient, register, login, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    await register("blocklist-outage@example.com", "correct-password")
    token = await login("blocklist-outage@example.com", "correct-password")

    monkeypatch.setattr("kalekit.auth.blocklist.get_redis", _dead_get_redis)
    response = await client.get("/v1/auth/me", headers=auth_header(token))

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Authentication service temporarily unavailable"
    }


@pytest.mark.asyncio(loop_scope="session")
async def test_blocklist_redis_failure_never_lets_the_request_through(
    client: AsyncClient, register, login, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: a valid, unrevoked token is still refused during the
    outage, because revocation can't be checked."""
    await register("blocklist-closed@example.com", "correct-password")
    token = await login("blocklist-closed@example.com", "correct-password")
    assert (
        await client.get("/v1/auth/me", headers=auth_header(token))
    ).status_code == 200

    monkeypatch.setattr("kalekit.auth.blocklist.get_redis", _dead_get_redis)

    assert (
        await client.get("/v1/auth/me", headers=auth_header(token))
    ).status_code == 503
