"""Fixed-window rate limiting on top of Redis.

Simple `INCR` + `EXPIRE` counter: cheap, and good enough for throttling
a low-volume, abuse-prone action like sending invitations. Not a
sliding window -- a caller could burst up to `limit` requests right at
a window boundary and again right after -- but that's an acceptable
trade for the extra complexity a sliding-window/token-bucket
implementation would add here.
"""

from __future__ import annotations

import redis.asyncio as redis


async def check_and_increment(
    r: redis.Redis, key: str, *, limit: int, window_seconds: int
) -> bool:
    """Increments `key`'s counter and reports whether it's still within
    `limit` for the current window.

    Returns True (and increments) when the call is allowed, False when
    the caller has already hit `limit` for this window -- the counter is
    still incremented in that case too, which is fine: it only matters
    that it stays >= limit until the window resets.
    """
    count = await r.incr(key)
    if count == 1:
        # First hit in this window -- (re)start the TTL. A crash between
        # INCR and EXPIRE would leave a key that never expires; harmless
        # here since it would just make that one key permanently
        # rate-limited rather than silently open, and is vanishingly
        # unlikely in practice.
        await r.expire(key, window_seconds)
    return count <= limit


__all__ = ["check_and_increment"]
