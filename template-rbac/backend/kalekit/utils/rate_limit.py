"""Fixed-window rate limiting on top of Redis.

Simple `INCR` + `EXPIRE` counter: cheap, and good enough for throttling
a low-volume, abuse-prone action like an auth endpoint. Not a sliding
window -- a caller could burst up to `limit` requests right at a window
boundary and again right after -- but that's an acceptable trade for the
extra complexity a sliding-window/token-bucket implementation would add
here.

Ported from template-abac's kalekit/utils/rate_limit.py (see issue #24 /
its invitation rate limit) rather than shared, since each template tree
is self-contained -- keep the two in sync if this primitive changes.
"""


from __future__ import annotations

import redis.asyncio as redis
from fastapi import Request

from kalekit.config import settings


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
        # rate-limit that IP/account/session with no way to reset.
        await r.expire(key, window_seconds)
    return count <= limit


def get_client_ip(request: Request) -> str:
    """Best-effort client IP for IP-keyed rate limiting.

    Only trusts the `X-Forwarded-For` header (set by Traefik in front of
    this API -- see compose.yml) when `settings.TRUST_PROXY_HEADERS` is
    on. Any client can set that header on a direct connection, so
    honoring it without a trusted proxy in front would let an attacker
    spoof a fresh IP on every request and bypass IP-based limiting
    entirely. Falls back to the ASGI-reported peer address, and to a
    fixed placeholder if even that is unavailable (e.g. some test
    transports) -- rate limiting is disabled by default in tests
    (`settings.RATE_LIMIT_ENABLED`), so that placeholder never needs to
    distinguish real callers.
    """
    if settings.TRUST_PROXY_HEADERS:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # The header is a comma-separated list appended to by every
            # hop; the first entry is the original client as seen by the
            # nearest trusted proxy.
            return forwarded_for.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


__all__ = ["check_and_increment", "get_client_ip"]
