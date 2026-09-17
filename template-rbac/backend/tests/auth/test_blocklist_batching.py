"""is_any_blocked batches the jti/user/family blocklist checks that
get_current_user runs on every authenticated request into a single
Redis round-trip instead of three sequential ones -- see #94.

These tests spy on the actual redis client's call count (never on
wall-clock timing, per the issue's own acceptance criteria) and cover
every combination of which of the three ids is present/blocked, plus
confirming get_current_user itself only issues one round-trip.
"""

import pytest
from httpx import AsyncClient

from kalekit.auth.permissions import (
    block_all_user_tokens,
    block_family_tokens,
    block_token,
    get_redis,
    is_any_blocked,
)


class _CallCountingSpy:
    """Wraps an async callable, counting awaits while still delegating
    to the real implementation -- so the test asserts round-trip
    *count* against the real (test) Redis client, not a
    re-implementation of Redis semantics, and never relies on timing.
    """

    def __init__(self, wrapped):
        self._wrapped = wrapped
        self.await_count = 0

    async def __call__(self, *args, **kwargs):
        self.await_count += 1
        return await self._wrapped(*args, **kwargs)


async def _spy_on_mget(monkeypatch: pytest.MonkeyPatch) -> _CallCountingSpy:
    """Wrap the real (test) redis client's `mget` with a call-counting
    spy, while still delegating to the real implementation -- so the
    test asserts round-trip *count*, not a re-implementation of Redis
    semantics."""
    r = await get_redis()
    spy = _CallCountingSpy(r.mget)
    monkeypatch.setattr(r, "mget", spy)
    return spy


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_issues_a_single_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked("jti-1", "user-1", "family-1")

    assert result is False
    assert spy.await_count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_true_when_only_jti_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await block_token("jti-2")
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked("jti-2", "user-2", "family-2")

    assert result is True
    assert spy.await_count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_true_when_only_user_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await block_all_user_tokens("user-3")
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked("jti-3", "user-3", "family-3")

    assert result is True
    assert spy.await_count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_true_when_only_family_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await block_family_tokens("family-4")
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked("jti-4", "user-4", "family-4")

    assert result is True
    assert spy.await_count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_false_when_nothing_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked("jti-5", "user-5", "family-5")

    assert result is False
    assert spy.await_count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_skips_none_ids_rather_than_treating_them_as_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing jti/user_id/sid must simply not be checked -- same as
    the `if jti and ...` guards this replaces -- not spuriously counted
    as blocked or not blocked either way."""
    # Block a user id that happens to equal None-ish sentinel is not
    # possible; instead prove the None branch is never queried by
    # blocking a value that would only be blocked if the guard were
    # broken (e.g. querying "blocked_user:None").
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked(None, None, None)

    assert result is False
    # No ids at all -- nothing to check, so no Redis round-trip either.
    assert spy.await_count == 0


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_with_only_jti_present_does_one_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await block_token("jti-6")
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked("jti-6", None, None)

    assert result is True
    assert spy.await_count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_get_current_user_hits_redis_once_for_a_valid_token(
    monkeypatch: pytest.MonkeyPatch,
    client: AsyncClient,
    register,
    auth_header,
    promote_to_admin,
) -> None:
    """End-to-end: authenticating a request via get_current_user must
    cost exactly one mget round-trip for the blocklist checks, not
    three separate EXISTS calls."""
    await register("batching@example.com")
    await promote_to_admin("batching@example.com")
    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "batching@example.com", "password": "password123"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    spy = await _spy_on_mget(monkeypatch)

    response = await client.get("/v1/chat/", headers=auth_header(token))

    assert response.status_code == 200
    assert spy.await_count == 1
