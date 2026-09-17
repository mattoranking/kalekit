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
    if count == 1 or await r.ttl(key) == -1:
        # (Re)start the TTL on the first hit in this window, and also
        # any time the key is somehow missing one (`ttl` returns -1 for
        # "exists, no expiry"). That second case recovers from a crash
        # between the INCR above and its EXPIRE on a previous call --
        # without it, such a key would never expire and permanently
        # rate-limit that org/user with no way to reset.
        await r.expire(key, window_seconds)
    return count <= limit


__all__ = ["check_and_increment"]
