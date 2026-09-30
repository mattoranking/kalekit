"""Every blocklist key must outlive the decoder's acceptance window.

The decoder accepts a token until exp + JWT_LEEWAY_SECONDS. A token from
the longest-lived client, blocked right after it was minted, is therefore
still decodable for (longest lifetime + leeway) seconds, and its block key
has to last at least that long.
"""

import pytest

from kalekit.auth.permissions import (
    block_families_tokens,
    block_family_tokens,
    block_token,
    get_redis,
)
from kalekit.config import settings

# Redis TTL is read back a moment after the SET; allow a little slack.
_SLACK_SECONDS = 5


def _required_ttl() -> int:
    return settings.access_token_max_expire_minutes() * 60 + settings.JWT_LEEWAY_SECONDS


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    ("block", "key"),
    [
        (lambda: block_token("ttl-jti"), "blocked_token:ttl-jti"),
        (lambda: block_family_tokens("ttl-family"), "blocked_family:ttl-family"),
        (
            lambda: block_families_tokens(["ttl-fam-a", "ttl-fam-b"]),
            "blocked_family:ttl-fam-b",
        ),
    ],
    ids=["token", "family", "families"],
)
async def test_block_key_outlives_expiry_plus_leeway(block, key: str) -> None:
    await block()

    r = await get_redis()
    ttl = await r.ttl(key)

    assert ttl >= _required_ttl() - _SLACK_SECONDS
    assert ttl <= _required_ttl()
