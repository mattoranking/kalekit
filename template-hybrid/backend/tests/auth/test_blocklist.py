import uuid

import pytest

from kalekit.auth.blocklist import (
    block_all_user_tokens,
    block_token,
    cache_refresh_grace_pair,
    get_cached_refresh_grace_pair,
    is_token_blocked,
    is_user_blocked,
)
from kalekit.redis import get_redis


@pytest.mark.asyncio(loop_scope="session")
async def test_token_is_not_blocked_until_blocked() -> None:
    jti = str(uuid.uuid4())
    assert await is_token_blocked(jti) is False

    await block_token(jti)
    assert await is_token_blocked(jti) is True


@pytest.mark.asyncio(loop_scope="session")
async def test_block_all_user_tokens_flags_the_user() -> None:
    """No endpoint calls this yet (no password-change / session-revoke-all
    / deactivation flow exists in this template), but the primitive
    itself -- the "kill all tokens now" escape hatch -- must work so it's
    ready to be wired up when one of those flows is added."""
    user_id = str(uuid.uuid4())
    other_user_id = str(uuid.uuid4())
    assert await is_user_blocked(user_id) is False

    await block_all_user_tokens(user_id)
    assert await is_user_blocked(user_id) is True
    assert await is_user_blocked(other_user_id) is False


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_grace_pair_round_trips() -> None:
    old_hash = f"hash-{uuid.uuid4()}"
    payload = {"access_token": "a", "refresh_token": "b", "token_type": "bearer"}

    assert await get_cached_refresh_grace_pair(old_hash) is None

    await cache_refresh_grace_pair(old_hash, payload, ttl_seconds=30)
    assert await get_cached_refresh_grace_pair(old_hash) == payload


@pytest.mark.asyncio(loop_scope="session")
async def test_corrupted_grace_cache_entry_is_treated_as_a_miss() -> None:
    """A malformed (non-JSON, or JSON-but-not-a-dict) cache entry must
    fall back to "no cached pair" -- the caller (refresh()'s grace-
    window branch) then fails closed with a 401 -- rather than raising
    and turning the request into an unhandled 500."""
    old_hash = f"hash-{uuid.uuid4()}"
    r = await get_redis()

    await r.set(f"refresh_grace:{old_hash}", "not-valid-json{{{", ex=30)
    assert await get_cached_refresh_grace_pair(old_hash) is None

    await r.set(f"refresh_grace:{old_hash}", "[1, 2, 3]", ex=30)
    assert await get_cached_refresh_grace_pair(old_hash) is None
