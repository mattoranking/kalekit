"""Redis outage behaviour for the call sites #99 left unguarded (#108).

* Logout (`block_token`) and the reuse-detection branch of refresh
  (`block_family_tokens`): fail CLOSED with a clean 503. The database
  revoke has already happened; the blocklist is Redis-only, so a silent
  skip would leave the access token usable.
* POST /oauth/exchange and the re-auth ticket: state lives only in
  Redis, so fail CLOSED with a clean 503 (same as the OAuth state paths).
* A corrupt cached role: a cache miss with database fallback, since
  Postgres is the source of truth.
"""

import json
from typing import Any

import pytest
import redis.exceptions
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import (
    _load_permissions_from_db,
    get_permissions_for_roles,
    get_redis,
    store_oauth_reauth_ticket,
)
from kalekit.auth.repository import find_user_by_email
from kalekit.auth.seed import ADMIN_ROLE, ensure_default_roles
from kalekit.config import settings
from tests.auth.test_reauthenticate import _oauth_only_login
from tests.oauth.test_endpoints import _mock_provider, _prime_state

_PASSWORD = "correct-password"


def _outage() -> redis.exceptions.ConnectionError:
    return redis.exceptions.ConnectionError("simulated redis outage")


class _FlakyRedis:
    """The real Redis, except the named commands raise ConnectionError."""

    def __init__(self, real: Any, fail: set[str]) -> None:
        self._real = real
        self._fail = fail

    def __getattr__(self, name: str):
        if name in self._fail:

            async def _fail(*args: object, **kwargs: object) -> None:
                raise _outage()

            return _fail
        return getattr(self._real, name)


async def _break_redis(
    monkeypatch: pytest.MonkeyPatch, fail: set[str], *modules: str
) -> None:
    real = await get_redis()

    async def _flaky_get_redis() -> _FlakyRedis:
        return _FlakyRedis(real, fail)

    for module in modules:
        monkeypatch.setattr(f"{module}.get_redis", _flaky_get_redis)


async def _login_pair(client: AsyncClient, register, email: str) -> tuple[str, str]:
    await register(email, _PASSWORD)
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": _PASSWORD}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


# --- Logout: fail closed ------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_returns_503_when_the_blocklist_write_fails(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    access, refresh = await _login_pair(client, register, "logout-outage@example.com")

    # Only the write fails: the blocklist read in get_current_user still
    # works, so the request reaches the logout handler itself.
    await _break_redis(monkeypatch, {"set"}, "kalekit.auth.permissions")
    response = await client.post(
        "/v1/auth/logout",
        json={"refresh_token": refresh},
        headers=auth_header(access),
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Could not complete sign-out, please try again"
    }


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_can_be_retried_once_redis_is_back(
    client: AsyncClient, register, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    access, refresh = await _login_pair(client, register, "logout-retry@example.com")

    with monkeypatch.context() as m:
        await _break_redis(m, {"set"}, "kalekit.auth.permissions")
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


# --- Refresh reuse detection: fail closed ------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_reuse_detection_returns_503_when_the_family_block_fails(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "REFRESH_TOKEN_GRACE_PERIOD_SECONDS", 0)
    _, refresh = await _login_pair(client, register, "reuse-outage@example.com")
    rotated = await client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    assert rotated.status_code == 200
    latest = rotated.json()["refresh_token"]

    with monkeypatch.context() as m:
        await _break_redis(
            m, {"set"}, "kalekit.auth.permissions", "kalekit.auth.endpoints"
        )
        replay = await client.post("/v1/auth/refresh", json={"refresh_token": refresh})

    assert replay.status_code == 503
    assert replay.json() == {"detail": "Could not complete sign-out, please try again"}
    # The database revoke ran before the failure: the family is dead.
    after = await client.post("/v1/auth/refresh", json={"refresh_token": latest})
    assert after.status_code == 401


# --- OAuth exchange: fail closed ---------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("failing_command", ["get", "delete"])
async def test_oauth_exchange_returns_503_when_redis_fails(
    failing_command: str, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_provider(monkeypatch)
    state = await _prime_state(client)
    callback = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "abc", "state": state},
        follow_redirects=False,
    )
    assert callback.status_code == 302
    code = callback.headers["location"].split("code=")[1]

    with monkeypatch.context() as m:
        await _break_redis(m, {failing_command}, "kalekit.oauth.endpoints")
        response = await client.post("/v1/oauth/exchange", json={"code": code})

    assert response.status_code == 503
    assert response.json() == {"detail": "OAuth sign-in is temporarily unavailable"}


# --- Re-auth ticket: fail closed ---------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_reauthenticate_returns_503_when_the_ticket_lookup_fails(
    client: AsyncClient,
    session: AsyncSession,
    auth_header,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "reauth-ticket-outage@example.com"
    access = await _oauth_only_login(
        client, session, monkeypatch, email, provider_id=808080
    )
    user = await find_user_by_email(session, email)
    assert user is not None
    await store_oauth_reauth_ticket("outage-ticket", str(user.id), ttl_seconds=60)

    with monkeypatch.context() as m:
        await _break_redis(m, {"getdel"}, "kalekit.auth.permissions")
        response = await client.post(
            "/v1/auth/reauthenticate",
            json={"oauth_ticket": "outage-ticket"},
            headers=auth_header(access),
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "OAuth sign-in is temporarily unavailable"}


# --- Corrupt cached role: cache miss, database fallback ----------------------


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "corrupt", ["{not json", '"admin"', "5", '{"a": 1}', "[1, 2]", "null-ish"]
)
async def test_corrupt_cached_role_falls_back_to_the_database(
    corrupt: str, session: AsyncSession
) -> None:
    await ensure_default_roles(session)
    expected = await _load_permissions_from_db(session, ADMIN_ROLE)
    assert expected
    r = await get_redis()
    key = f"role:{ADMIN_ROLE}:permissions"
    await r.set(key, corrupt)

    assert await get_permissions_for_roles(session, [ADMIN_ROLE]) == expected
    # The bad entry was overwritten with the database's answer.
    assert set(json.loads(await r.get(key))) == expected
