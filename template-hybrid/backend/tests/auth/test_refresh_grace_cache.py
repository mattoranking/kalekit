"""Resilience coverage for the refresh grace-window Redis cache (#92).

`cache_refresh_grace_pair` / `get_cached_refresh_grace_pair` are
best-effort: the DB rotation is already done by the time either runs,
and the cache only lets a second, concurrent legitimate refresh replay
the same about-to-be-rotated token without tripping reuse detection. A
Redis outage, or a corrupt cached value, must degrade to "no cached
pair" -- never turn a successful refresh into an unhandled 500.

Note the cache write in `refresh()` is inline, before the commit (see
the note in that function), so an error there would otherwise abort
the whole request and roll back a valid rotation.
"""

import json

import pytest
import redis.exceptions
from httpx import AsyncClient

from kalekit.auth.blocklist import (
    cache_refresh_grace_pair,
    get_cached_refresh_grace_pair,
)
from kalekit.redis import get_redis


class _BoomRedis:
    """Every command raises, simulating an outage."""

    async def set(self, *args, **kwargs):
        raise redis.exceptions.ConnectionError("simulated redis outage")

    async def get(self, *args, **kwargs):
        raise redis.exceptions.ConnectionError("simulated redis outage")


class _ValueRedis:
    """`get` returns a fixed (possibly unusable) cached value."""

    def __init__(self, value: str) -> None:
        self.value = value

    async def get(self, *args, **kwargs):
        return self.value


def _patch_redis(monkeypatch: pytest.MonkeyPatch, fake: object) -> None:
    async def _get_redis():
        return fake

    monkeypatch.setattr("kalekit.auth.blocklist.get_redis", _get_redis)


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_write_survives_a_redis_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_redis(monkeypatch, _BoomRedis())

    # Must not raise.
    await cache_refresh_grace_pair("some-hash", {"a": 1}, ttl_seconds=45)


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_read_survives_a_redis_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_redis(monkeypatch, _BoomRedis())

    assert await get_cached_refresh_grace_pair("some-hash") is None


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "value",
    [
        "not valid json",
        "[1, 2, 3]",
        json.dumps({"refresh_token": "abc", "token_type": "bearer"}),
        json.dumps({"access_token": 1, "refresh_token": "abc"}),
    ],
    ids=["not-json", "non-dict", "missing-field", "wrong-type"],
)
async def test_cache_read_treats_an_unusable_value_as_a_miss(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    _patch_redis(monkeypatch, _ValueRedis(value))

    assert await get_cached_refresh_grace_pair("some-hash") is None


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_round_trip_still_works() -> None:
    pair = {"access_token": "a", "refresh_token": "r", "token_type": "bearer"}

    await cache_refresh_grace_pair("round-trip-hash", pair, ttl_seconds=45)

    assert await get_cached_refresh_grace_pair("round-trip-hash") == pair


class _GraceKeysFailRedis:
    """Delegates to the real Redis, except that reads and writes of the
    grace-cache keys raise -- so the rest of the request path (login,
    etc.) keeps working while only the cache is 'down'."""

    def __init__(self, real, *, fail_set: bool, fail_get: bool) -> None:
        self._real = real
        self._fail_set = fail_set
        self._fail_get = fail_get

    async def set(self, name, *args, **kwargs):
        if self._fail_set and str(name).startswith("refresh_grace:"):
            raise redis.exceptions.ConnectionError("simulated redis outage")
        return await self._real.set(name, *args, **kwargs)

    async def get(self, name, *args, **kwargs):
        if self._fail_get and str(name).startswith("refresh_grace:"):
            raise redis.exceptions.ConnectionError("simulated redis outage")
        return await self._real.get(name, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


async def _login_refresh_token(client: AsyncClient, email: str) -> str:
    await client.post(
        "/v1/auth/register", json={"email": email, "password": "password123"}
    )
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "password123"}
    )
    assert response.status_code == 200, response.text
    return response.json()["refresh_token"]


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_succeeds_when_the_grace_cache_write_fails(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cache write is inline, before commit: a Redis error there
    must not turn a valid rotation into a 500."""
    refresh_token = await _login_refresh_token(client, "grace-write@example.com")
    real = await get_redis()
    _patch_redis(monkeypatch, _GraceKeysFailRedis(real, fail_set=True, fail_get=False))

    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert response.status_code == 200, response.text
    assert response.json()["refresh_token"] != refresh_token


@pytest.mark.asyncio(loop_scope="session")
async def test_grace_replay_fails_closed_when_the_cache_read_fails(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replay inside the grace window with the cache unreachable
    gets the existing fail-closed 401, not a 500."""
    refresh_token = await _login_refresh_token(client, "grace-read@example.com")
    first = await client.post("/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert first.status_code == 200
    real = await get_redis()
    _patch_redis(monkeypatch, _GraceKeysFailRedis(real, fail_set=False, fail_get=True))

    replay = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert replay.status_code == 401, replay.text
