"""Redis outage behaviour for OAuth (#99).

The CSRF state, the one-time exchange code and the re-auth ticket live
only in Redis, so there is nothing to degrade to: OAuth fails CLOSED,
but as a clean 503 rather than an unhandled 500. Password login never
touches this state and must keep working.
"""

import pytest
import redis.exceptions
from httpx import AsyncClient

from kalekit.auth.permissions import get_redis
from tests.oauth.test_endpoints import _mock_provider, _prime_state

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
async def test_callback_returns_503_when_storing_the_exchange_code_fails(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_provider(monkeypatch)
    state = await _prime_state(client)
    real = await get_redis()

    class _SetFails:
        async def get(self, *args: object, **kwargs: object):
            return await real.get(*args, **kwargs)

        async def delete(self, *args: object, **kwargs: object):
            return await real.delete(*args, **kwargs)

        async def set(self, *args: object, **kwargs: object) -> None:
            raise _outage()

    async def _get_redis() -> _SetFails:
        return _SetFails()

    monkeypatch.setattr("kalekit.oauth.endpoints.get_redis", _get_redis)

    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "abc", "state": state},
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert response.json() == _UNAVAILABLE


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_returns_503_when_storing_the_reauth_ticket_fails(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_provider(monkeypatch)
    authorize = await client.get(
        "/v1/oauth/github/authorize", params={"reauth": "true"}
    )
    assert authorize.status_code == 200
    from urllib.parse import parse_qs, urlsplit

    state = parse_qs(urlsplit(authorize.json()["authorization_url"]).query)["state"][0]

    async def _fail(*args: object, **kwargs: object) -> None:
        raise _outage()

    monkeypatch.setattr("kalekit.oauth.endpoints.store_oauth_reauth_ticket", _fail)

    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "abc", "state": state},
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert response.json() == _UNAVAILABLE


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
