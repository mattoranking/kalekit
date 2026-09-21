"""Redis outage behaviour for OAuth (#106, port of RBAC #99).

The CSRF state lives only in Redis, so there is nothing to degrade to:
OAuth fails CLOSED, but as a clean 503 rather than an unhandled 500.
Password login never touches this state and must keep working.
"""

import pytest
import redis.exceptions
from httpx import AsyncClient

_UNAVAILABLE = {"detail": "OAuth sign-in is temporarily unavailable"}


def _outage() -> redis.exceptions.ConnectionError:
    return redis.exceptions.ConnectionError("simulated redis outage")


class _DeadRedis:
    def __getattr__(self, name: str):
        async def _fail(*args: object, **kwargs: object) -> None:
            raise _outage()

        return _fail


async def _dead_get_redis() -> _DeadRedis:
    return _DeadRedis()


@pytest.mark.asyncio(loop_scope="session")
async def test_authorize_returns_503_when_redis_is_down(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("kalekit.oauth.endpoints.get_redis", _dead_get_redis)

    response = await client.get("/v1/oauth/github/authorize")

    assert response.status_code == 503
    assert response.json() == _UNAVAILABLE


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_returns_503_when_redis_is_down(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("kalekit.oauth.endpoints.get_redis", _dead_get_redis)

    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "abc", "state": "whatever"},
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert response.json() == _UNAVAILABLE


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_still_rejects_unknown_state_with_400_when_redis_is_up(
    client: AsyncClient,
) -> None:
    """The 400 raised inside the guarded block must not be turned into a 503."""
    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "abc", "state": "never-issued"},
        follow_redirects=False,
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_password_login_still_works_while_oauth_redis_is_down(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    await register("oauth-outage-pw@example.com", "correct-password")
    monkeypatch.setattr("kalekit.oauth.endpoints.get_redis", _dead_get_redis)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "oauth-outage-pw@example.com", "password": "correct-password"},
    )

    assert response.status_code == 200
