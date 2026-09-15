import json

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.config import settings

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
    """Fetch permissions for a list of roles from Redis."""
    r = await get_redis()
    permissions: set[str] = set()
    for role in roles:
        cached = await r.get(f"role:{role}:permissions")
        if cached:
            permissions.update(json.loads(cached))
        else:
            # Cache miss - load from DB then cache
            perms: set[str] = await _load_permissions_from_db(session, role)
            await r.set(
                f"role:{role}:permissions",
                json.dumps(list(perms)),
                ex=300,  # 5 min TTL
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
    ttl = ttl_seconds or settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    await r.set(f"{_BLOCKLIST_PREFIX}{jti}", "1", ex=ttl)


async def is_token_blocked(jti: str) -> bool:
    """Check if a token JTI has been revoked."""
    r = await get_redis()
    return await r.exists(f"{_BLOCKLIST_PREFIX}{jti}") > 0


async def block_all_user_tokens(user_id: str) -> None:
    """Flag a user so the middleware rejects any access token.

    Unlike per-JTI blocking, this covers tokens whose JTI we
    don't know (e.g., compromised account). The middleware
    checks this flag alongside the per-JTI blocklist.
    TTL matches access token lifetime.
    """
    r = await get_redis()
    ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    await r.set(f"blocked_user:{user_id}", "1", ex=ttl)
