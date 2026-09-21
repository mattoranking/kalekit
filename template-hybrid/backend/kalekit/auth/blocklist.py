"""Emergency access-token revocation.

Access tokens are stateless JWTs that stay valid until they expire, so
there is normally no way to invalidate one early. This module gives us
two Redis-backed escape hatches, checked by `get_current_user` on every
request:

- `block_token` / `is_token_blocked`: revoke one specific access token
  by its `jti` (used on logout, so the token that called `/auth/logout`
  stops working immediately instead of remaining valid for the rest of
  its lifetime).
- `block_all_user_tokens` / `is_user_blocked`: revoke every access token
  a user currently holds, regardless of `jti` (for an emergency "kill
  all sessions now" on a compromised account -- e.g. password change,
  a "log out everywhere" action, or deactivation). Nothing in this
  template calls it yet since those flows don't exist here, but it's
  wired into `get_current_user` so adding one later is a one-line call.

Both use a TTL matching the access token lifetime, since there's no
point keeping an entry around after the token it blocks would have
expired anyway.
"""

import json

import structlog
from redis.exceptions import RedisError

from kalekit.config import settings
from kalekit.redis import get_redis

logger = structlog.get_logger()

_BLOCKLIST_PREFIX = "blocked_token:"
_USER_BLOCKLIST_PREFIX = "blocked_user:"


async def block_token(jti: str, ttl_seconds: int | None = None) -> None:
    """Add a token JTI to the blocklist.

    TTL defaults to the access token lifetime so entries
    auto-expire once the token would have expired anyway.
    """
    r = await get_redis()
    ttl = ttl_seconds or settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    await r.set(f"{_BLOCKLIST_PREFIX}{jti}", "1", ex=ttl)


async def is_token_blocked(jti: str) -> bool:
    """Check if a token JTI has been revoked."""
    r = await get_redis()
    return await r.exists(f"{_BLOCKLIST_PREFIX}{jti}") > 0


async def block_all_user_tokens(user_id: str) -> None:
    """Flag a user so get_current_user rejects any access token.

    Unlike per-JTI blocking, this covers tokens whose JTI we
    don't know (e.g., compromised account). get_current_user
    checks this flag alongside the per-JTI blocklist.
    TTL matches access token lifetime.
    """
    r = await get_redis()
    ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    await r.set(f"{_USER_BLOCKLIST_PREFIX}{user_id}", "1", ex=ttl)


async def is_user_blocked(user_id: str) -> bool:
    """Check if all of this user's tokens were flagged as revoked."""
    r = await get_redis()
    return await r.exists(f"{_USER_BLOCKLIST_PREFIX}{user_id}") > 0


# ---------------------------------------------------------------------------
# Refresh grace window: let two concurrent /auth/refresh calls presenting
# the same (about-to-be-rotated) token both get back the identical new
# pair, instead of the second one being treated as reuse.
# ---------------------------------------------------------------------------

_REFRESH_GRACE_PREFIX = "refresh_grace:"


async def cache_refresh_grace_pair(
    old_token_hash: str, payload: dict, ttl_seconds: int
) -> None:
    """Remember the (access_token, refresh_token) pair issued when
    `old_token_hash` was rotated, keyed by the token that was rotated
    away. A second caller racing in with the same old token within
    `ttl_seconds` gets this exact pair back instead of a fresh one, so
    both callers end up holding the same, single new refresh token.
    """
    if ttl_seconds <= 0:
        # A zero/negative grace period means the feature is effectively
        # disabled -- nothing to cache.
        return
    try:
        r = await get_redis()
        await r.set(
            f"{_REFRESH_GRACE_PREFIX}{old_token_hash}",
            json.dumps(payload),
            ex=ttl_seconds,
        )
    except RedisError:
        # Best-effort only: this cache just smooths over a *second*,
        # concurrent legitimate refresh of the same about-to-be-rotated
        # token (see refresh() in kalekit.auth.endpoints). A Redis
        # outage must not turn an otherwise-successful refresh into a
        # 500 (the write is inline, before commit, so it would also
        # roll back a valid rotation); this one rotation simply loses
        # grace-window leniency.
        logger.warning("refresh_grace_cache_write_failed", exc_info=True)


async def get_cached_refresh_grace_pair(old_token_hash: str) -> dict | None:
    try:
        r = await get_redis()
        cached = await r.get(f"{_REFRESH_GRACE_PREFIX}{old_token_hash}")
    except RedisError:
        logger.warning("refresh_grace_cache_read_failed", exc_info=True)
        return None
    if cached is None:
        return None
    try:
        decoded = json.loads(cached)
    except (TypeError, ValueError):
        # Corrupt cached value: treat as a miss. The caller already
        # fails closed with a 401 on None, which is the right outcome
        # for an ambiguous (not confirmed-reuse) case.
        logger.warning("refresh_grace_cache_value_corrupt", exc_info=True)
        return None
    if (
        not isinstance(decoded, dict)
        or not isinstance(decoded.get("access_token"), str)
        or not isinstance(decoded.get("refresh_token"), str)
    ):
        # Valid JSON but not the TokenResponse shape this cache only
        # ever holds; treat as a miss too.
        logger.warning("refresh_grace_cache_value_malformed")
        return None
    return decoded
