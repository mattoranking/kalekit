"""is_any_blocked batches the jti/user/family blocklist checks that
get_current_user runs on every authenticated request into a single
Redis round-trip instead of three sequential ones -- see #94.

These tests spy on the actual redis client's call count (never on
wall-clock timing, per the issue's own acceptance criteria). With all
three ids present, every one of the 8 subsets of {jti, user, family}
that could independently be blocked is covered; a couple of missing-id
edge cases (all absent, only jti present) are covered separately.
get_current_user itself is also checked end-to-end to confirm it only
issues one round-trip.
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
@pytest.mark.parametrize(
    "blocked",
    [
        frozenset(),
        frozenset({"jti"}),
        frozenset({"user"}),
        frozenset({"family"}),
        frozenset({"jti", "user"}),
        frozenset({"jti", "family"}),
        frozenset({"user", "family"}),
        frozenset({"jti", "user", "family"}),
    ],
    ids=[
        "none-blocked",
        "jti-only",
        "user-only",
        "family-only",
        "jti-and-user",
        "jti-and-family",
        "user-and-family",
        "all-three",
    ],
)
async def test_is_any_blocked_covers_every_combination_of_blocked_ids(
    monkeypatch: pytest.MonkeyPatch,
    blocked: frozenset[str],
) -> None:
    """With all three ids present on the token, every one of the 8
    subsets of {jti, user, family} that could independently be blocked
    must still resolve correctly (True iff at least one of the
    *blocked* ones is in the subset) in exactly one Redis round-trip.
    """
    jti, user_id, family_id = "jti-x", "user-x", "family-x"
    if "jti" in blocked:
        await block_token(jti)
    if "user" in blocked:
        await block_all_user_tokens(user_id)
    if "family" in blocked:
        await block_family_tokens(family_id)

    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked(jti, user_id, family_id)

    assert result is (len(blocked) > 0)
    assert spy.await_count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_is_any_blocked_skips_none_ids_rather_than_treating_them_as_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing jti/user_id/sid must simply not be checked -- same as
    the `if jti and ...` guards this replaces -- not spuriously counted
    as blocked or not blocked either way. With every id absent, there is
    nothing to check at all, so no Redis round-trip should happen
    either (asserted below via the spy's call count)."""
    spy = await _spy_on_mget(monkeypatch)

    result = await is_any_blocked(None, None, None)

    assert result is False
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
        json={"email": "batching@example.com", "password": "password12345"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    spy = await _spy_on_mget(monkeypatch)

    response = await client.get("/v1/chat/", headers=auth_header(token))

    assert response.status_code == 200
    assert spy.await_count == 1
