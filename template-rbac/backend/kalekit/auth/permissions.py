import json

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
        )
    return _redis


async def get_permissions_for_roles(
    session: AsyncSession,
    roles: list[str],
) -> set[str]:
    """Fetch permissions for a list of roles, Redis cache first.

    Redis is only a performance cache; Postgres is the source of truth.
    A Redis error on the read is treated as a cache miss, and one on the
    write-back just skips caching, so an outage degrades to one DB query
    per role (still correct) instead of a 500 (#98).
    """
    permissions: set[str] = set()
    for role in roles:
        key = f"role:{role}:permissions"
        cached = None
        try:
            r = await get_redis()
            cached = await r.get(key)
        except RedisError:
            logger.warning(
                "role_permission_cache_read_failed", role=role, exc_info=True
            )
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
        # Cache miss (or Redis unavailable) - load from DB then cache
        perms: set[str] = await _load_permissions_from_db(session, role)
        try:
            r = await get_redis()
            await r.set(
                key,
                json.dumps(list(perms)),
                ex=settings.ROLE_CACHE_TTL_SECONDS,
            )
        except RedisError:
            # The check already succeeded via the DB; a failed cache
            # write must not turn it into an error.
            logger.warning(
                "role_permission_cache_write_failed", role=role, exc_info=True
            )
        permissions.update(perms)
    return permissions


async def _load_permissions_from_db(
    session: AsyncSession, role_name: str
) -> set[str]:
    """Fallback: query DB and populate Redis.

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
        select(Permission.name)
        .join(RolePermission)
        .join(Role)
        .where(Role.name == role_name)
    )
    result = await session.execute(stmt)
    return {row[0] for row in result.all()}


async def invalidate_role_cache(role_name: str) -> None:
    """Call this when role permissions are updated."""
    r = await get_redis()
    await r.delete(f"role:{role_name}:permissions")


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


async def block_token(jti: str, ttl_seconds: int | None = None) -> None:
    """Add a token JTI to the blocklist.

    TTL defaults to the access token lifetime so entries
    auto-expire once the token would have expired anyway.
    """
    r = await get_redis()
    ttl = ttl_seconds or settings.access_token_max_expire_minutes() * 60
    await r.set(f"{_BLOCKLIST_PREFIX}{jti}", "1", ex=ttl)


async def block_all_user_tokens(user_id: str) -> None:
    """Flag a user so get_current_user rejects any access token.

    Unlike per-JTI blocking, this covers tokens whose JTI we
    don't know (e.g., compromised account). get_current_user
    checks this flag alongside the per-JTI blocklist.
    TTL matches access token lifetime.
    """
    r = await get_redis()
    ttl = settings.access_token_max_expire_minutes() * 60
    await r.set(f"blocked_user:{user_id}", "1", ex=ttl)


async def block_family_tokens(family_id: str, ttl_seconds: int | None = None) -> None:
    """Flag a single session (token family) so get_current_user rejects
    any access token minted under it -- even ones whose jti we don't
    know. Access tokens carry the family_id that minted them as the
    `sid` claim (see create_access_token), which is what lets this be
    scoped to one session instead of blocking every session the user
    has the way block_all_user_tokens does. Used when a specific
    session is revoked (DELETE /auth/sessions/{id}) or when other
    sessions are killed on password change while the current one is
    kept. TTL matches access token lifetime.
    """
    r = await get_redis()
    ttl = (
        ttl_seconds
        if ttl_seconds is not None
        else settings.access_token_max_expire_minutes() * 60
    )
    await r.set(f"blocked_family:{family_id}", "1", ex=ttl)


async def is_any_blocked(
    jti: str | None, user_id: str | None, family_id: str | None
) -> bool:
    """Combined jti/user/family blocklist check in a single Redis
    round-trip, for get_current_user's hot path (see #94).

    Checks whether the token's JTI, the user, or the token's family has
    been blocked, but instead of three sequential `EXISTS` round-trips
    it issues one `MGET` across whichever of the three keys apply. An
    id that's None (absent from the token) is simply not checked --
    same as the `if jti and ...` guards this replaces at the call
    site -- rather than treated as blocked or not blocked either way.
    """
    keys = []
    if jti:
        keys.append(f"{_BLOCKLIST_PREFIX}{jti}")
    if user_id:
        keys.append(f"blocked_user:{user_id}")
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
