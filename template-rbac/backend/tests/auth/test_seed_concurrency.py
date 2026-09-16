import asyncio
import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.scope import SCOPES_SUPPORTED
from kalekit.auth.seed import (
    ADMIN_ROLE,
    VISITOR_ROLE,
    _get_or_create_permission,
    _get_or_create_role,
    ensure_default_roles,
)
from kalekit.models.role import Permission, Role, RolePermission


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_role_creation_does_not_500(engine: AsyncEngine) -> None:
    """Two coroutines racing `_get_or_create_role` for a brand-new role name
    (the exact shape of two simultaneous first-time /auth/register calls
    seeding the 'visitor' role in `ensure_default_roles`) must both return
    successfully -- neither should see an unhandled IntegrityError from the
    loser's INSERT landing after the winner's has committed.

    Each coroutine gets its own `AsyncSession` (its own connection), unlike
    the shared-session `client`/`session` fixtures used elsewhere, so the
    two INSERTs are genuinely concurrent at the database level rather than
    serialized through one connection.
    """
    role_name = f"race-role-{uuid.uuid4().hex}"
    barrier = asyncio.Barrier(2)

    async def create_role() -> Role:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            # Force this session to acquire its pooled connection *before*
            # the barrier, so the race is decided by the SELECT/INSERT
            # interleaving we actually care about, not by incidental
            # connection-acquisition latency (which can otherwise
            # accidentally serialize the two coroutines and hide the bug).
            await session.connection()
            await barrier.wait()
            role = await _get_or_create_role(session, role_name, "race test role")
            await session.commit()
            return role

    try:
        role_a, role_b = await asyncio.gather(create_role(), create_role())

        assert role_a.id == role_b.id

        async with AsyncSession(engine) as verify_session:
            result = await verify_session.execute(
                select(Role).where(Role.name == role_name)
            )
            rows = result.scalars().all()
            assert len(rows) == 1
    finally:
        async with AsyncSession(engine) as cleanup_session:
            await cleanup_session.execute(delete(Role).where(Role.name == role_name))
            await cleanup_session.commit()


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_permission_creation_does_not_500(
    engine: AsyncEngine,
) -> None:
    """Same race as above, but for `_get_or_create_permission`."""
    permission_name = f"race:permission:{uuid.uuid4().hex}"
    barrier = asyncio.Barrier(2)

    async def create_permission() -> Permission:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            await session.connection()
            await barrier.wait()
            permission = await _get_or_create_permission(session, permission_name)
            await session.commit()
            return permission

    try:
        permission_a, permission_b = await asyncio.gather(
            create_permission(), create_permission()
        )

        assert permission_a.id == permission_b.id

        async with AsyncSession(engine) as verify_session:
            result = await verify_session.execute(
                select(Permission).where(Permission.name == permission_name)
            )
            rows = result.scalars().all()
            assert len(rows) == 1
    finally:
        async with AsyncSession(engine) as cleanup_session:
            await cleanup_session.execute(
                delete(Permission).where(Permission.name == permission_name)
            )
            await cleanup_session.commit()


async def _delete_default_roles(engine: AsyncEngine) -> None:
    """Remove any committed 'visitor'/'admin' rows (and their admin
    RolePermission/Permission rows) so a test can start from a genuinely
    fresh database regardless of what other concurrency tests in this
    session already committed -- unlike the rest of the suite, these
    tests commit for real (see module docstring reasoning) so they can't
    rely on the usual per-test rollback for isolation.
    """
    async with AsyncSession(engine) as session:
        admin_row = (
            await session.execute(select(Role).where(Role.name == ADMIN_ROLE))
        ).scalar_one_or_none()

        if admin_row is not None:
            await session.execute(
                delete(RolePermission).where(RolePermission.role_id == admin_row.id)
            )

        await session.execute(
            delete(Role).where(Role.name.in_([VISITOR_ROLE, ADMIN_ROLE]))
        )
        await session.execute(
            delete(Permission).where(Permission.name.in_(list(SCOPES_SUPPORTED)))
        )

        await session.commit()


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_ensure_default_roles_against_fresh_db(
    engine: AsyncEngine,
) -> None:
    """The full `ensure_default_roles` race: two coroutines standing in for
    two simultaneous first-time registrations against a database that has
    never seeded 'visitor'/'admin' yet. Both must complete cleanly with no
    unhandled IntegrityError, from the role rows themselves *and* from the
    admin role's RolePermission join-table population, which races the
    same way.
    """
    await _delete_default_roles(engine)

    barrier = asyncio.Barrier(2)

    async def seed() -> tuple[Role, Role]:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            await session.connection()
            await barrier.wait()
            visitor, admin = await ensure_default_roles(session)
            await session.commit()
            return visitor, admin

    try:
        (visitor_a, admin_a), (visitor_b, admin_b) = await asyncio.gather(
            seed(), seed()
        )

        assert visitor_a.id == visitor_b.id
        assert admin_a.id == admin_b.id

        async with AsyncSession(engine) as verify_session:
            roles = (
                await verify_session.execute(
                    select(Role).where(Role.name.in_([VISITOR_ROLE, ADMIN_ROLE]))
                )
            ).scalars().all()
            assert len(roles) == 2

            role_permissions = (
                await verify_session.execute(
                    select(RolePermission).where(
                        RolePermission.role_id == admin_a.id
                    )
                )
            ).scalars().all()
            assert len(role_permissions) == len(SCOPES_SUPPORTED)
    finally:
        await _delete_default_roles(engine)
