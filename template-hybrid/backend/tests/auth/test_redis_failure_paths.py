"""Redis outage behaviour for the paths with no database fallback (#107,
port of RBAC #99).

Each group needs its own failure direction, so each is pinned here:

* Revocation blocklist (`get_current_user`): fail CLOSED with a 503.
  Revocation state lives only in Redis, so a token can't be told from a
  revoked one; honouring it would keep stolen sessions alive.
* Invitation rate limiting: fail OPEN. It is an abuse control, not an
  authorization gate, so an outage must not take the endpoint down.

The OAuth state failure paths live in tests/oauth/test_redis_failure.py.
"""

import pytest
import redis.exceptions
from httpx import AsyncClient

from kalekit.utils.rate_limit import rate_limit_fails_open


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


@pytest.mark.asyncio(loop_scope="session")
async def test_revoked_token_is_still_a_401_when_redis_is_healthy(
    client: AsyncClient, register, auth_header
) -> None:
    await register("blocklist-healthy@example.com", "correct-password")
    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "blocklist-healthy@example.com", "password": "correct-password"},
    )
    token = login_response.json()["access_token"]
    logout = await client.post("/v1/auth/logout", headers=auth_header(token))
    assert logout.status_code == 204

    response = await client.get("/v1/auth/me", headers=auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "Token has been revoked"


# --- Rate limiting: fail open ------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_invitation_is_allowed_when_the_rate_limiter_redis_is_down(
    client: AsyncClient,
    register,
    login,
    auth_header,
    org_id_for,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The invitation behaves as if rate limiting were off: it reaches
    the handler and gets its normal 202 (not a 500, not a 429)."""
    await register("invite-outage@example.com", "correct-password")
    token = await login("invite-outage@example.com", "correct-password")
    org = await org_id_for("invite-outage@example.com")

    # Only the endpoint's own limiter connection is broken; auth (the
    # blocklist) keeps using the healthy Redis, so the outcome isolates
    # the rate-limit failure path.
    monkeypatch.setattr("kalekit.organization.endpoints.get_redis", _dead_get_redis)

    response = await client.post(
        f"/v1/organizations/{org}/invitations",
        json={"email": "invitee-outage@example.com", "role": "member"},
        headers=auth_header(token),
    )

    assert response.status_code == 202, response.text


def test_rate_limit_fails_open_swallows_only_redis_errors() -> None:
    with rate_limit_fails_open("test"):
        raise _outage()

    with pytest.raises(ValueError):
        with rate_limit_fails_open("test"):
            raise ValueError("not a redis error")
