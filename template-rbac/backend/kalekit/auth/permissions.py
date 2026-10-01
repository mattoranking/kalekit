import json
from collections.abc import Iterable

import redis.asyncio as redis
import structlog
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.config import settings

logger = structlog.get_logger()

_redis: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT_SECONDS,
        )
    return _redis


async def get_permissions_for_roles(
    session: AsyncSession,
    roles: list[str],
) -> set[str]:
    """Fetch permissions for a list of roles, Redis cache first.

    Redis is only a performance cache; Postgres is the source of truth.
    The cache is read with one MGET for all roles, the roles it does not
    answer are loaded with one DB query, and the results are written back
    in one pipeline (#128). A Redis error on the read is treated as a
    cache miss for every role, and one on the write-back just skips
    caching, so an outage degrades to one DB query (still correct)
    instead of a 500 (#98).
    """
    unique_roles = list(dict.fromkeys(roles))
    if not unique_roles:
        return set()

    keys = [_role_cache_key(role) for role in unique_roles]
    cached_values: list[str | None] = [None] * len(keys)
    try:
        r = await get_redis()
        cached_values = await r.mget(keys)
    except RedisError:
        logger.warning("role_permission_cache_read_failed", exc_info=True)

    permissions: set[str] = set()
    missing: list[str] = []
    for role, cached in zip(unique_roles, cached_values, strict=True):
        if cached:
            try:
                decoded = json.loads(cached)
                if not isinstance(decoded, list) or not all(
                    isinstance(p, str) for p in decoded
                ):
                    raise ValueError("cached permissions are not a list of strings")
                permissions.update(decoded)
                continue
            except (ValueError, TypeError):
                # A truthy but corrupt entry (bad JSON, or JSON that is
                # not a list of strings) is a cache miss, not an error
                # (#108): reload from the DB and overwrite it below.
                logger.warning(
                    "role_permission_cache_corrupt", role=role, exc_info=True
                )
        missing.append(role)

    if not missing:
        return permissions

    # Cache miss (or Redis unavailable) - load from DB then cache
    loaded = await _load_permissions_from_db_bulk(session, missing)
    try:
        r = await get_redis()
        async with r.pipeline(transaction=False) as pipe:
            for role in missing:
                pipe.set(
                    _role_cache_key(role),
                    json.dumps(list(loaded[role])),
                    ex=settings.ROLE_CACHE_TTL_SECONDS,
                )
            await pipe.execute()
    except RedisError:
        # The check already succeeded via the DB; a failed cache
        # write must not turn it into an error.
        logger.warning("role_permission_cache_write_failed", exc_info=True)
    for role in missing:
        permissions.update(loaded[role])
    return permissions


def _role_cache_key(role: str) -> str:
    return f"role:{role}:permissions"


async def _load_permissions_from_db_bulk(
    session: AsyncSession, role_names: list[str]
) -> dict[str, set[str]]:
    """Fallback: load the permissions of every role in `role_names` with a
    single query. A role that does not exist, or has no permissions, maps
    to an empty set.

    Uses the caller's own session/transaction rather than opening a
    separate engine and connection -- a role's permissions granted
    earlier in the same request (or the same test transaction) must be
    visible here without needing a commit first.
    """
    from kalekit.models.role import (
        Permission,
        Role,
        RolePermission,
    )
    from kalekit.sql import select

    stmt = (
        select(Role.name, Permission.name)
        .select_from(RolePermission)
        .join(Role, Role.id == RolePermission.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(Role.name.in_(role_names))
    )
    result = await session.execute(stmt)
    loaded: dict[str, set[str]] = {name: set() for name in role_names}
    for role_name, permission_name in result.all():
        loaded[role_name].add(permission_name)
    return loaded


async def _load_permissions_from_db(
    session: AsyncSession, role_name: str
) -> set[str]:
    """One role's permissions straight from the DB (no cache)."""
    return (await _load_permissions_from_db_bulk(session, [role_name]))[role_name]


async def invalidate_role_cache(role_name: str) -> None:
    """Call this when role permissions are updated."""
    r = await get_redis()
    await r.delete(f"role:{role_name}:permissions")


async def invalidate_role_caches(role_names: Iterable[str]) -> None:
    """Drop the cached permissions of several roles with one DEL. Raises a
    RedisError when Redis is unreachable; callers that must not fail on
    that catch it."""
    keys = [_role_cache_key(name) for name in role_names]
    if not keys:
        return
    r = await get_redis()
    await r.delete(*keys)


# ---------------------------------------------------------------------------
# Scope resolution: roles → validated Scope enum values
# ---------------------------------------------------------------------------

async def get_scopes_for_roles(
    session: AsyncSession, roles: list[str]
) -> set[str]:
    """Resolve roles to validated scope strings.

    Fetches raw permissions via the Redis-cached RBAC lookup,
    then filters to only those that match a known Scope member.
    Unknown permissions (legacy, typos) are silently dropped.
    """
    from kalekit.auth.scope import Scope

    raw_permissions = await get_permissions_for_roles(session, roles)
    scopes: set[str] = set()
    for perm in raw_permissions:
        try:
            scopes.add(Scope(perm).value)
        except ValueError:
            continue
    return scopes


# ---------------------------------------------------------------------------
# Token blocklist: for emergency revocation of access tokens
# ---------------------------------------------------------------------------

_BLOCKLIST_PREFIX = "blocked_token:"


def _default_ttl_seconds() -> int:
    """How long a block must live: the longest access token lifetime plus
    the decoder's clock-skew leeway. The decoder accepts a token until
    exp + JWT_LEEWAY_SECONDS, and a token can be blocked right after it
    was minted, so a TTL of just the lifetime would let a blocked token
    work again before the decoder rejects it."""
    return settings.access_token_max_expire_minutes() * 60 + settings.JWT_LEEWAY_SECONDS


async def block_token(jti: str, ttl_seconds: int | None = None) -> None:
    """Add a token JTI to the blocklist.

    TTL defaults to the access token lifetime plus decoder leeway, so
    entries auto-expire once the decoder would reject the token anyway.
    """
    r = await get_redis()
    ttl = ttl_seconds or _default_ttl_seconds()
    await r.set(f"{_BLOCKLIST_PREFIX}{jti}", "1", ex=ttl)


async def block_family_tokens(family_id: str, ttl_seconds: int | None = None) -> None:
    """Flag a single session (token family) so get_current_user rejects
    any access token minted under it -- even ones whose jti we don't
    know. Access tokens carry the family_id that minted them as the
    `sid` claim (see create_access_token), which is what lets this be
    scoped to one session instead of every session the user has.
    Used when a specific
    session is revoked (DELETE /auth/sessions/{id}) or when other
    sessions are killed on password change while the current one is
    kept. TTL is the same as for block_token.
    """
    r = await get_redis()
    ttl = ttl_seconds if ttl_seconds is not None else _default_ttl_seconds()
    await r.set(f"blocked_family:{family_id}", "1", ex=ttl)


async def block_families_tokens(
    family_ids: Iterable[str], ttl_seconds: int | None = None
) -> None:
    """`block_family_tokens` for several sessions at once: every SET goes
    out in one pipeline, so revoking N sessions is one Redis round trip
    instead of N (#129). Like the single version it raises RedisError on
    a failure and does not swallow it: the caller decides how to fail
    closed. An empty list makes no Redis call.
    """
    ids = list(family_ids)
    if not ids:
        return
    r = await get_redis()
    ttl = ttl_seconds if ttl_seconds is not None else _default_ttl_seconds()
    async with r.pipeline(transaction=False) as pipe:
        for family_id in ids:
            pipe.set(f"blocked_family:{family_id}", "1", ex=ttl)
        await pipe.execute()


async def is_any_blocked(jti: str | None, family_id: str | None) -> bool:
    """Combined jti/family blocklist check in a single Redis round-trip,
    for get_current_user's hot path (see #94).

    Checks whether the token's JTI or the token's family has been
    blocked, but instead of two sequential `EXISTS` round-trips it
    issues one `MGET` across whichever of the two keys apply. An id
    that's None (absent from the token) is simply not checked rather
    than treated as blocked or not blocked either way.

    There is no user-wide key: "sign out everywhere" is the
    `users.token_version` cut-off in get_current_user (#195, #229).
    """
    keys = []
    if jti:
        keys.append(f"{_BLOCKLIST_PREFIX}{jti}")
    if family_id:
        keys.append(f"blocked_family:{family_id}")

    if not keys:
        return False

    r = await get_redis()
    values = await r.mget(keys)
    return any(v is not None for v in values)


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
        # 500; this one rotation simply loses grace-window leniency.
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
        # Valid JSON but not the TokenResponse shape; the caller does
        # TokenResponse(**cached), which would raise (-> 500).
        logger.warning("refresh_grace_cache_value_malformed")
        return None
    return decoded


# ---------------------------------------------------------------------------
# OAuth re-authentication tickets (#16): proof that an OAuth-only user
# (no password_hash to re-enter) just completed a fresh provider login,
# for POST /auth/reauthenticate. Minted by /oauth/{provider}/callback's
# `reauth` branch, handed to the frontend in the redirect the same
# ticket-not-tokens way /oauth/exchange's code is, and consumed exactly
# once by /auth/reauthenticate.
# ---------------------------------------------------------------------------

_OAUTH_REAUTH_PREFIX = "oauth_reauth:"


async def store_oauth_reauth_ticket(
    ticket: str, user_id: str, ttl_seconds: int
) -> None:
    r = await get_redis()
    await r.set(f"{_OAUTH_REAUTH_PREFIX}{ticket}", user_id, ex=ttl_seconds)


async def consume_oauth_reauth_ticket(ticket: str) -> str | None:
    """Look up and delete-on-use the user_id behind a fresh-OAuth-login
    ticket. None if the ticket is unknown/expired/already used -- same
    single-use shape as /oauth/exchange's code, so a leaked or replayed
    ticket can't grant step-up access twice.

    Uses GETDEL (atomic) rather than a separate GET + DELETE -- two
    concurrent consumers hitting GET-then-DELETE could otherwise both
    read the ticket before either deleted it, letting it be replayed
    once per racing caller instead of truly single-use.

    Requires Redis >= 6.2 (GETDEL was added in that release); this
    template pins `redis:7-alpine` in compose.yml, well above that
    floor, so no older-Redis fallback is provided here.
    """
    r = await get_redis()
    key = f"{_OAUTH_REAUTH_PREFIX}{ticket}"
    return await r.getdel(key)
