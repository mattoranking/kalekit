import uuid

import pytest

from kalekit.auth.blocklist import block_all_user_tokens, block_token, is_any_blocked
from kalekit.config import settings
from kalekit.redis import get_redis


@pytest.mark.asyncio(loop_scope="session")
async def test_token_is_not_blocked_until_blocked() -> None:
    jti = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    assert await is_any_blocked(jti, user_id) is False

    await block_token(jti)
    assert await is_any_blocked(jti, user_id) is True
    # Blocking one jti says nothing about another token of the same user.
    assert await is_any_blocked(str(uuid.uuid4()), user_id) is False


@pytest.mark.asyncio(loop_scope="session")
async def test_block_all_user_tokens_flags_the_user() -> None:
    """No endpoint calls this yet (no password-change / session-revoke-all
    / deactivation flow exists in this template), but the primitive
    itself -- the "kill all tokens now" escape hatch -- must work so it's
    ready to be wired up when one of those flows is added."""
    user_id = str(uuid.uuid4())
    other_user_id = str(uuid.uuid4())
    assert await is_any_blocked(str(uuid.uuid4()), user_id) is False

    await block_all_user_tokens(user_id)
    assert await is_any_blocked(str(uuid.uuid4()), user_id) is True
    assert await is_any_blocked(str(uuid.uuid4()), other_user_id) is False


@pytest.mark.asyncio(loop_scope="session")
async def test_absent_ids_are_not_checked() -> None:
    assert await is_any_blocked(None, None) is False

    user_id = str(uuid.uuid4())
    await block_all_user_tokens(user_id)
    assert await is_any_blocked(None, user_id) is True


@pytest.mark.asyncio(loop_scope="session")
async def test_check_is_a_single_redis_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check runs on every authenticated request, so jti and user
    are read with one MGET, not two EXISTS calls."""
    real = await get_redis()
    calls: list[str] = []

    class _Counting:
        def __getattr__(self, name: str):
            attr = getattr(real, name)
            if not callable(attr):
                return attr

            async def _wrapped(*args: object, **kwargs: object):
                calls.append(name)
                return await attr(*args, **kwargs)

            return _wrapped

    async def _get_redis() -> _Counting:
        return _Counting()

    monkeypatch.setattr("kalekit.auth.blocklist.get_redis", _get_redis)

    assert await is_any_blocked(str(uuid.uuid4()), str(uuid.uuid4())) is False
    assert calls == ["mget"]


@pytest.mark.asyncio(loop_scope="session")
async def test_block_keys_outlive_the_token_including_leeway() -> None:
    """The decoder accepts a token until exp + JWT_LEEWAY_SECONDS, and a
    token can be blocked right after it was minted, so the block key must
    live for the full lifetime plus the leeway or the token works again
    before the decoder rejects it."""
    jti = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    await block_token(jti)
    await block_all_user_tokens(user_id)

    r = await get_redis()
    minimum = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60 + settings.JWT_LEEWAY_SECONDS
    assert await r.ttl(f"blocked_token:{jti}") >= minimum - 1
    assert await r.ttl(f"blocked_user:{user_id}") >= minimum - 1
