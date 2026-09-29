"""Emergency access-token revocation.

Access tokens are stateless JWTs that stay valid until they expire, so
there is normally no way to invalidate one early. This module gives us
two Redis-backed escape hatches, checked by `get_current_user` on every
request through `is_any_blocked`:

- `block_token`: revoke one specific access token by its `jti` (used on
  logout, so the token that called `/auth/logout` stops working
  immediately instead of remaining valid for the rest of its lifetime).
- `block_all_user_tokens`: revoke every access token a user currently
  holds, regardless of `jti` (for an emergency "kill all sessions now"
  on a compromised account -- e.g. password change, a "log out
  everywhere" action, or deactivation). Nothing in this template calls
  it yet since those flows don't exist here, but it's wired into
  `get_current_user` so adding one later is a one-line call.

Both use a TTL of the access token lifetime plus the JWT leeway, since there's no
point keeping an entry around after the token it blocks would have
expired anyway.
"""

from kalekit.config import settings
from kalekit.redis import get_redis

_BLOCKLIST_PREFIX = "blocked_token:"
_USER_BLOCKLIST_PREFIX = "blocked_user:"


def _default_ttl_seconds() -> int:
    """How long a block must live: the token lifetime plus the decoder's
    clock-skew leeway. The decoder accepts a token until
    exp + JWT_LEEWAY_SECONDS, and a token can be blocked right after it
    was minted, so a TTL of just the lifetime would let a blocked token
    work again before the decoder rejects it."""
    return settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60 + settings.JWT_LEEWAY_SECONDS


async def block_token(jti: str, ttl_seconds: int | None = None) -> None:
    """Add a token JTI to the blocklist.

    TTL defaults to the access token lifetime plus the JWT leeway, so
    entries auto-expire once the decoder would reject the token anyway.
    """
    r = await get_redis()
    ttl = ttl_seconds or _default_ttl_seconds()
    await r.set(f"{_BLOCKLIST_PREFIX}{jti}", "1", ex=ttl)


async def block_all_user_tokens(user_id: str) -> None:
    """Flag a user so get_current_user rejects any access token.

    Unlike per-JTI blocking, this covers tokens whose JTI we
    don't know (e.g., compromised account). get_current_user
    checks this flag alongside the per-JTI blocklist.
    TTL is the same as for block_token.
    """
    r = await get_redis()
    ttl = _default_ttl_seconds()
    await r.set(f"{_USER_BLOCKLIST_PREFIX}{user_id}", "1", ex=ttl)


async def is_any_blocked(jti: str | None, user_id: str | None) -> bool:
    """Combined jti/user blocklist check in a single Redis round-trip,
    for get_current_user's hot path (same shape as RBAC's, see #94).

    One `MGET` across whichever of the two keys apply, instead of two
    sequential `EXISTS` calls. An id that's None (absent from the token)
    is simply not checked.
    """
    keys = []
    if jti:
        keys.append(f"{_BLOCKLIST_PREFIX}{jti}")
    if user_id:
        keys.append(f"{_USER_BLOCKLIST_PREFIX}{user_id}")

    if not keys:
        return False

    r = await get_redis()
    values = await r.mget(keys)
    return any(v is not None for v in values)
