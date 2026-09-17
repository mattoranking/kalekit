"""Resilience coverage for the refresh grace-window Redis cache.

`cache_refresh_grace_pair`/`get_cached_refresh_grace_pair` are best
-effort: the actual token rotation already committed to the DB by the
time either is called, and the cache only exists to let a second,
concurrent legitimate refresh replay the same about-to-be-rotated
token within the grace window without tripping reuse detection. A
transient Redis outage (or an unexpected/corrupt cached value) must
degrade this gracefully -- not turn an otherwise-successful refresh
into an unhandled 500. See the round-3 Copilot review on PR #87.
"""

import json

import pytest
import redis.exceptions

from kalekit.auth.service import (
    cache_refresh_grace_pair,
    get_cached_refresh_grace_pair,
)


class _BoomRedis:
    """A fake Redis client whose every command raises, simulating an
    outage/connection failure rather than a clean miss."""

    async def set(self, *args, **kwargs):
        raise redis.exceptions.ConnectionError("simulated redis outage")

    async def get(self, *args, **kwargs):
        raise redis.exceptions.ConnectionError("simulated redis outage")


class _CorruptRedis:
    """A fake Redis client that returns a value get_cached_refresh_
    grace_pair can't parse as JSON -- simulating a corrupted key
    rather than a clean miss (None)."""

    async def get(self, *args, **kwargs):
        return "not valid json"


class _WrongShapeRedis:
    """A fake Redis client that returns *valid* JSON, but not the
    TokenResponse shape (access_token/refresh_token strings) the
    caller assumes -- e.g. a JSON list."""

    async def get(self, *args, **kwargs):
        return "[1, 2, 3]"


class _MissingFieldRedis:
    """Valid JSON object, but missing the required `access_token`
    field -- constructing TokenResponse(**this) would raise."""

    async def get(self, *args, **kwargs):
        return json.dumps({"refresh_token": "abc", "token_type": "bearer"})


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_write_survives_a_redis_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom_get_redis():
        return _BoomRedis()

    monkeypatch.setattr(
        "kalekit.auth.service.get_redis", _boom_get_redis
    )

    # Must not raise -- a caller mid-/auth/refresh, right after
    # committing a successful rotation, shouldn't have that turned
    # into a 500 just because the best-effort cache write failed.
    await cache_refresh_grace_pair("some-hash", {"a": 1}, ttl_seconds=45)


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_read_survives_a_redis_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom_get_redis():
        return _BoomRedis()

    monkeypatch.setattr(
        "kalekit.auth.service.get_redis", _boom_get_redis
    )

    # Must return None (the same as a clean cache miss), not raise --
    # the caller's existing "cache entry expired/evicted" handling
    # already fails closed with a 401 on None, which is the correct
    # outcome for an unreachable cache too.
    result = await get_cached_refresh_grace_pair("some-hash")

    assert result is None


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_read_treats_a_corrupt_value_as_a_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _corrupt_get_redis():
        return _CorruptRedis()

    monkeypatch.setattr(
        "kalekit.auth.service.get_redis", _corrupt_get_redis
    )

    result = await get_cached_refresh_grace_pair("some-hash")

    assert result is None


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_read_treats_a_non_dict_value_as_a_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid JSON that isn't the TokenResponse shape (a list, here)
    must not be handed back to the caller as-is -- `TokenResponse(
    **cached)` on a list would raise, turning this into a 500 instead
    of the intended fail-closed 401 for an unreadable cache."""

    async def _wrong_shape_get_redis():
        return _WrongShapeRedis()

    monkeypatch.setattr(
        "kalekit.auth.service.get_redis", _wrong_shape_get_redis
    )

    result = await get_cached_refresh_grace_pair("some-hash")

    assert result is None


@pytest.mark.asyncio(loop_scope="session")
async def test_cache_read_treats_a_dict_missing_required_fields_as_a_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _missing_field_get_redis():
        return _MissingFieldRedis()

    monkeypatch.setattr(
        "kalekit.auth.service.get_redis", _missing_field_get_redis
    )

    result = await get_cached_refresh_grace_pair("some-hash")

    assert result is None
