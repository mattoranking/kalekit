"""A Redis that accepts the connection and never answers (#157).

Without socket timeouts redis-py waits forever for the reply, so the
blocklist check on an authenticated request hangs the API. With them the
read raises `redis.exceptions.TimeoutError` (a `RedisError`), which the
fail-closed handler from #99 turns into the same 503 as an outage.
"""

import asyncio
from collections.abc import AsyncGenerator, Callable

import pytest
import pytest_asyncio
from httpx import AsyncClient

from kalekit import redis as redis_module
from kalekit.config import settings

TIMEOUT = 0.3
# The test's own deadline: on the old code the request never returns, so
# this turns a hang into a failure instead of stalling the suite.
DEADLINE = 5.0


@pytest_asyncio.fixture(loop_scope="session")
async def hung_redis_url() -> AsyncGenerator[str]:
    """A local server that accepts connections and never replies."""
    writers: list[asyncio.StreamWriter] = []

    async def _accept_and_stay_silent(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writers.append(writer)
        try:
            await reader.read()  # blocks until the client goes away
        finally:
            writer.close()

    server = await asyncio.start_server(_accept_and_stay_silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"redis://127.0.0.1:{port}/0"
    finally:
        server.close()
        for writer in writers:
            writer.close()
        await server.wait_closed()


@pytest_asyncio.fixture(loop_scope="session")
async def point_client_at(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[Callable[[str], None]]:
    """Make get_redis() build a fresh client for a given URL, and close it."""

    def _point(url: str) -> None:
        monkeypatch.setattr(settings, "REDIS_URL", url)
        monkeypatch.setattr(
            settings, "REDIS_SOCKET_TIMEOUT_SECONDS", TIMEOUT, raising=False
        )
        monkeypatch.setattr(
            settings, "REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS", TIMEOUT, raising=False
        )
        monkeypatch.setattr(redis_module, "_redis", None)

    yield _point

    created = redis_module._redis
    if created is not None:
        await created.aclose()


@pytest.mark.asyncio(loop_scope="session")
async def test_hung_redis_fails_closed_within_the_timeout(
    client: AsyncClient,
    register,
    login,
    auth_header,
    hung_redis_url: str,
    point_client_at: Callable[[str], None],
) -> None:
    await register("hung-redis@example.com", "correct-password")
    token = await login("hung-redis@example.com", "correct-password")

    point_client_at(hung_redis_url)
    started = asyncio.get_running_loop().time()
    response = await asyncio.wait_for(
        client.get("/v1/auth/me", headers=auth_header(token)), timeout=DEADLINE
    )
    elapsed = asyncio.get_running_loop().time() - started

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Authentication service temporarily unavailable"
    }
    assert elapsed < DEADLINE / 2


@pytest.mark.asyncio(loop_scope="session")
async def test_client_gets_both_timeouts_from_settings(
    point_client_at: Callable[[str], None],
) -> None:
    point_client_at("redis://127.0.0.1:1/0")

    client = await redis_module.get_redis()
    kwargs = client.connection_pool.connection_kwargs

    assert kwargs["socket_timeout"] == TIMEOUT
    assert kwargs["socket_connect_timeout"] == TIMEOUT
