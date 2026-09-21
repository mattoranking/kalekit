"""Redis outage behaviour for the paths with no database fallback (#99).

Each group needs its own failure direction, so each is pinned here:

* Revocation blocklist (`get_current_user`): fail CLOSED with a 503.
  Revocation state lives only in Redis, so a token can't be told from a
  revoked one; honouring it would keep stolen sessions alive.
* Rate limiting: fail OPEN. It is an abuse control, not an authorization
  gate, so an outage must not take every rate-limited endpoint down.

The OAuth state failure paths live in tests/oauth/test_redis_failure.py.
Healthy-Redis behaviour is covered by the existing suites (e.g.
test_rate_limit.py, test_logout.py).
"""

import pytest
import redis.exceptions
from httpx import AsyncClient

from kalekit.config import settings


def _outage() -> redis.exceptions.ConnectionError:
    return redis.exceptions.ConnectionError("simulated redis outage")


class _DeadRedis:
    """Every command raises, like a Redis that has gone away."""

    def __getattr__(self, name: str):
        async def _fail(*args: object, **kwargs: object) -> None:
            raise _outage()

        return _fail


async def _dead_get_redis() -> _DeadRedis:
    return _DeadRedis()


# --- Revocation blocklist: fail closed, cleanly ------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_blocklist_redis_failure_returns_503_not_500(
    client: AsyncClient, register, login, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    await register("blocklist-outage@example.com", "correct-password")
    token = await login("blocklist-outage@example.com", "correct-password")

    monkeypatch.setattr("kalekit.auth.permissions.get_redis", _dead_get_redis)
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

    monkeypatch.setattr("kalekit.auth.permissions.get_redis", _dead_get_redis)

    assert (
        await client.get("/v1/auth/me", headers=auth_header(token))
    ).status_code == 503


@pytest.mark.asyncio(loop_scope="session")
async def test_revoked_token_is_still_a_401_when_redis_is_healthy(
    client: AsyncClient, register, login, auth_header
) -> None:
    await register("blocklist-healthy@example.com", "correct-password")
    token = await login("blocklist-healthy@example.com", "correct-password")
    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "blocklist-healthy@example.com", "password": "correct-password"},
    )
    refresh_token = login_response.json()["refresh_token"]
    token = login_response.json()["access_token"]
    logout = await client.post(
        "/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers=auth_header(token),
    )
    assert logout.status_code == 204

    response = await client.get("/v1/auth/me", headers=auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "Token has been revoked"


# --- Rate limiting: fail open ------------------------------------------------

_PASSWORD = "correct-password"


async def _login_pair(client: AsyncClient, email: str) -> tuple[str, str]:
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": _PASSWORD}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "endpoint",
    [
        "register",
        "login_success",
        "login_wrong_password",
        "refresh",
        "resend_verification",
        "reauthenticate_success",
        "reauthenticate_wrong_password",
        "forgot_password",
        "reset_password",
    ],
)
async def test_rate_limited_endpoints_allow_the_request_when_redis_is_down(
    endpoint: str,
    client: AsyncClient,
    register,
    auth_header,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each rate-limited endpoint behaves exactly as if rate limiting
    were off: the request reaches the handler and gets its normal
    answer (not a 500 from the Redis error, not a 429)."""
    email = f"rl-outage-{endpoint}@example.com"
    await register(email, _PASSWORD)
    access, refresh = await _login_pair(client, email)

    # Only the endpoints' own limiter connection is broken; auth (the
    # blocklist) keeps using the healthy Redis, so the outcome isolates
    # the rate-limit failure path.
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr("kalekit.auth.endpoints.get_redis", _dead_get_redis)

    headers = auth_header(access)
    if endpoint == "register":
        response = await client.post(
            "/v1/auth/register",
            json={"email": "rl-outage-new@example.com", "password": _PASSWORD},
        )
        expected = 201
    elif endpoint == "login_success":
        response = await client.post(
            "/v1/auth/login", json={"email": email, "password": _PASSWORD}
        )
        expected = 200
    elif endpoint == "login_wrong_password":
        response = await client.post(
            "/v1/auth/login", json={"email": email, "password": "wrong-password"}
        )
        expected = 401
    elif endpoint == "refresh":
        response = await client.post(
            "/v1/auth/refresh", json={"refresh_token": refresh}
        )
        expected = 200
    elif endpoint == "resend_verification":
        response = await client.post("/v1/auth/resend-verification", headers=headers)
        expected = 200
    elif endpoint == "reauthenticate_success":
        response = await client.post(
            "/v1/auth/reauthenticate", json={"password": _PASSWORD}, headers=headers
        )
        expected = 200
    elif endpoint == "reauthenticate_wrong_password":
        response = await client.post(
            "/v1/auth/reauthenticate", json={"password": "wrong"}, headers=headers
        )
        expected = 401
    elif endpoint == "forgot_password":
        response = await client.post("/v1/auth/password/forgot", json={"email": email})
        expected = 202
    else:  # reset_password: a bogus token reaching the token check == allowed
        response = await client.post(
            "/v1/auth/password/reset",
            json={"token": "not-a-real-token", "new_password": "new-password123"},
        )
        expected = 400

    assert response.status_code == expected, response.text
