"""The test suite must never flush Redis db 0 (issue #201). The guard in
conftest checks the index the client really uses, so URL forms that
redis-py resolves to db 0 are refused too."""

import pytest
from redis.asyncio import Redis

from tests.conftest import assert_not_redis_db_0


@pytest.mark.parametrize(
    "url",
    [
        "redis://localhost:6379",
        "redis://localhost:6379/0",
        "redis://localhost:6379/0/",
        "redis://localhost:6379/00",
        "redis://localhost:6379/15?db=0",
        "unix:///tmp/redis.sock",
    ],
)
def test_guard_refuses_urls_that_resolve_to_db_0(url: str) -> None:
    with pytest.raises(AssertionError, match="db 0"):
        assert_not_redis_db_0(Redis.from_url(url))


def test_guard_allows_a_dedicated_test_index() -> None:
    assert_not_redis_db_0(Redis.from_url("redis://localhost:6379/15"))
