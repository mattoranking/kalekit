"""require_permission must resolve the caller's permissions live on
every request (Redis role cache -> DB fallback) rather than trusting
the access token's baked-in `scopes` claim -- see #6. These tests prove
a role/permission change takes effect on the very next request, using
the same still-valid access token throughout (proving the *token*
isn't what changed -- the live lookup is)."""

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import invalidate_role_cache
from kalekit.auth.repository import find_user_by_email
from kalekit.auth.seed import ADMIN_ROLE
from kalekit.config import settings
from kalekit.models.role import Role, RolePermission, UserRole


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio(loop_scope="session")
async def test_removing_admin_role_blocks_admin_routes_on_the_next_request(
    client: AsyncClient,
    register,
    login,
    promote_to_admin,
    session: AsyncSession,
) -> None:
    email = "live-permissions@example.com"
    await register(email)
    await promote_to_admin(email)
    token = await login(email, client_type="admin")

    still_admin = await client.get("/v1/users/", headers=_auth(token))
    assert still_admin.status_code == 200

    # Revoke the admin role directly, without touching the token at
    # all -- it's still the exact same access token used above, whose
    # `scopes` claim still (incorrectly, if trusted) says this user has
    # every admin permission.
    user = await find_user_by_email(session, email)
    assert user is not None
    await session.execute(
        delete(UserRole).where(UserRole.user_id == user.id)
    )
    await session.flush()
    # The test harness reuses this one `session` for the whole request
    # lifecycle (see conftest.py), so `user.roles` (lazy="selectin")
    # would otherwise still show the already-loaded, now-stale roles
    # list from before the delete above -- refresh it to see what a
    # fresh request in production actually would.
    await session.refresh(user, attribute_names=["roles"])

    blocked = await client.get("/v1/users/", headers=_auth(token))
    assert blocked.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_revoking_a_permission_blocks_it_next_request_after_cache_invalidation(
    client: AsyncClient,
    register,
    login,
    promote_to_admin,
    session: AsyncSession,
) -> None:
    """Removing `users:read` from the admin role -- and invalidating
    the Redis cache for it, as any endpoint that edits role permissions
    must -- blocks a still-admin user from an endpoint gated on that
    permission, using the same access token as before."""
    email = "live-role-permission@example.com"
    await register(email)
    await promote_to_admin(email)
    token = await login(email, client_type="admin")

    still_allowed = await client.get("/v1/users/", headers=_auth(token))
    assert still_allowed.status_code == 200

    result = await session.execute(select(Role).where(Role.name == ADMIN_ROLE))
    admin_role = result.scalar_one()
    await session.execute(
        delete(RolePermission).where(
            RolePermission.role_id == admin_role.id,
        )
    )
    await session.flush()
    await invalidate_role_cache(ADMIN_ROLE)

    blocked = await client.get("/v1/users/", headers=_auth(token))
    assert blocked.status_code == 403


def test_role_cache_ttl_is_short() -> None:
    """Documents the shortened role-permission cache TTL (#6): the
    staleness window a caller can be exposed to between a role's
    permissions changing and invalidate_role_cache not having been
    called is now this short, not the previous 5 minutes."""
    assert settings.ROLE_CACHE_TTL_SECONDS <= 60
