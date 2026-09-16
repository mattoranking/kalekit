import uuid

import pytest

from kalekit.auth.blocklist import (
    block_all_user_tokens,
    block_token,
    is_token_blocked,
    is_user_blocked,
)


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
