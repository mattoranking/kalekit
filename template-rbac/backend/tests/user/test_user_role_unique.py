"""user_roles holds each (user, role) pair at most once (#242).

The database refuses a duplicate row, and the two code paths that insert
user_roles rows (`assign_role`, `replace_user_roles`) treat a duplicate as
"already done" instead of failing the request.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.auth.scope import SCOPES_SUPPORTED
from kalekit.auth.seed import assign_role, ensure_default_roles
from kalekit.models.role import Permission, Role, RolePermission, UserRole
from kalekit.models.user import User
from kalekit.user.service import replace_user_roles


async def _count(session: AsyncSession, user_id: uuid.UUID) -> int:
    return (
        await session.execute(
            select(func.count())
            .select_from(UserRole)
            .where(UserRole.user_id == user_id)
        )
    ).scalar_one()


@pytest.mark.asyncio(loop_scope="session")
async def test_database_refuses_a_duplicate_user_role_row(
    session: AsyncSession, register
) -> None:
    await register("dup-db@example.com")
    user = await find_user_by_email(session, "dup-db@example.com")
    assert user is not None
    visitor, _ = await ensure_default_roles(session)

    # register already gave the user the visitor role.
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await session.execute(
                insert(UserRole).values(
                    id=uuid.uuid4(), user_id=user.id, role_id=visitor.id
                )
            )


@pytest.mark.asyncio(loop_scope="session")
async def test_assign_role_twice_is_a_no_op(session: AsyncSession, register) -> None:
    await register("dup-assign@example.com")
    user = await find_user_by_email(session, "dup-assign@example.com")
    assert user is not None
    visitor, _ = await ensure_default_roles(session)

    await assign_role(session, user, visitor)

    assert await _count(session, user.id) == 1
    # The session is still usable after the swallowed conflict.
    _, admin = await ensure_default_roles(session)
    await assign_role(session, user, admin)
    assert await _count(session, user.id) == 2


@pytest.mark.asyncio(loop_scope="session")
async def test_replace_user_roles_ignores_a_row_it_could_not_see(
    session: AsyncSession, register
) -> None:
    """The user's roles were read before another request added the admin
    row, so the insert hits the unique constraint."""
    await register("dup-replace@example.com")
    user = await find_user_by_email(session, "dup-replace@example.com")
    assert user is not None
    visitor, admin = await ensure_default_roles(session)
    assert {ur.role_id for ur in user.roles} == {visitor.id}

    await session.execute(
        insert(UserRole).values(id=uuid.uuid4(), user_id=user.id, role_id=admin.id)
    )

    await replace_user_roles(session, user, [visitor, admin])

    assert await _count(session, user.id) == 2
    assert {ur.role_id for ur in user.roles} == {visitor.id, admin.id}


@pytest_asyncio.fixture(loop_scope="session")
async def committed_user(engine: AsyncEngine) -> AsyncGenerator[uuid.UUID]:
    async with AsyncSession(engine, expire_on_commit=False) as s:
        user = User(id=uuid.uuid4(), email=f"race-{uuid.uuid4().hex[:8]}@unique.test")
        s.add(user)
        # Committed first, so the racing sessions below do not each hold
        # an uncommitted insert of the same role row.
        await ensure_default_roles(s)
        await s.commit()
    try:
        yield user.id
    finally:
        async with AsyncSession(engine) as s:
            await s.execute(delete(UserRole).where(UserRole.user_id == user.id))
            await s.execute(delete(User).where(User.id == user.id))
            ids = select(Role.id).where(Role.name.in_(["visitor", "admin"]))
            await s.execute(
                delete(RolePermission).where(RolePermission.role_id.in_(ids))
            )
            await s.execute(delete(Role).where(Role.name.in_(["visitor", "admin"])))
            await s.execute(
                delete(Permission).where(Permission.name.in_(list(SCOPES_SUPPORTED)))
            )
            await s.commit()


@pytest.mark.asyncio(loop_scope="session")
async def test_two_racing_replace_user_roles_both_succeed(
    engine: AsyncEngine, committed_user: uuid.UUID
) -> None:
    """Two requests that both saw no roles each insert the same rows."""
    barrier = asyncio.Barrier(2)

    async def replace() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as s:
            _, admin = await ensure_default_roles(s)
            user = await s.get(User, committed_user)
            assert user is not None
            await s.refresh(user, ["roles"])
            await barrier.wait()
            await replace_user_roles(s, user, [admin])
            await s.commit()

    await asyncio.gather(replace(), replace())

    async with AsyncSession(engine) as s:
        assert await _count(s, committed_user) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_replace_user_roles_removes_every_row_of_a_legacy_duplicate(
    session: AsyncSession, register
) -> None:
    """A database created before the constraint can still hold two rows for
    one (user, role). create_all does not add the constraint to an existing
    table and there are no migrations, so removing the role must take both."""
    await register("dup-legacy@example.com")
    user = await find_user_by_email(session, "dup-legacy@example.com")
    assert user is not None
    visitor, admin = await ensure_default_roles(session)
    # Rolled back with the test's transaction (Postgres DDL is transactional).
    await session.execute(
        text("ALTER TABLE user_roles DROP CONSTRAINT user_roles_user_id_role_id_key")
    )
    for _ in range(2):
        await session.execute(
            insert(UserRole).values(id=uuid.uuid4(), user_id=user.id, role_id=admin.id)
        )
    await session.refresh(user, ["roles"])

    await replace_user_roles(session, user, [visitor])

    assert {ur.role_id for ur in user.roles} == {visitor.id}
    assert await _count(session, user.id) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_assign_role_does_not_swallow_a_foreign_key_failure(
    session: AsyncSession,
) -> None:
    visitor, _ = await ensure_default_roles(session)
    ghost = User(id=uuid.uuid4(), email="ghost@example.com")  # never inserted

    with pytest.raises(IntegrityError):
        await assign_role(session, ghost, visitor)
