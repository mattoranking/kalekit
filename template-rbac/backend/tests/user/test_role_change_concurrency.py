"""Overlapping admin changes, in separate committing sessions.

The rest of the suite runs in one rolled-back transaction, which cannot
show a race. Each task here gets its own connection, and the first task
holds its transaction open (after doing its work, before committing)
while the second starts, so the second really does overlap the first.
Rows are committed for real, so every test removes what it created.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.seed import ADMIN_ROLE, ensure_default_roles
from kalekit.models.role import Role, UserRole
from kalekit.models.user import User
from kalekit.user.service import change_user_roles, ensure_not_last_active_admin


@pytest_asyncio.fixture(loop_scope="session")
async def two_admins(engine: AsyncEngine) -> AsyncGenerator[tuple[User, User]]:
    """Two committed, active admins. Removed afterwards."""
    tag = uuid.uuid4().hex[:8]
    async with AsyncSession(engine, expire_on_commit=False) as s:
        # Other committed admins (none expected) would hide the race.
        existing = (
            await s.execute(
                select(User.id)
                .join(UserRole, UserRole.user_id == User.id)
                .join(Role, Role.id == UserRole.role_id)
                .where(Role.name == ADMIN_ROLE, User.is_active.is_(True))
            )
        ).all()
        assert existing == [], "committed admins left behind by another test"
        _, admin_role = await ensure_default_roles(s)
        users = []
        for name in ("a", "b"):
            user = User(id=uuid.uuid4(), email=f"{name}-{tag}@race.test")
            s.add(user)
            await s.flush()
            s.add(UserRole(user_id=user.id, role_id=admin_role.id))
            users.append(user)
        await s.commit()
    try:
        yield users[0], users[1]
    finally:
        ids = [u.id for u in users]
        async with AsyncSession(engine) as s:
            await s.execute(delete(UserRole).where(UserRole.user_id.in_(ids)))
            await s.execute(delete(User).where(User.id.in_(ids)))
            await s.commit()


async def _active_admin_ids(engine: AsyncEngine) -> set[uuid.UUID]:
    async with AsyncSession(engine) as s:
        rows = await s.execute(
            select(User.id)
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(Role.name == ADMIN_ROLE, User.is_active.is_(True))
        )
        return set(rows.scalars().all())


async def _run_overlapping(first, second) -> tuple[object, object]:
    """Run `first(session)` and leave its transaction open until `second`
    has started and had time to reach its own checks, then commit."""
    started = asyncio.Event()
    release = asyncio.Event()

    async def run_first() -> object:
        async with first.engine_session() as s:
            try:
                result = await first.work(s)
            except HTTPException as exc:
                await s.rollback()
                started.set()
                return exc
            started.set()
            await release.wait()
            await s.commit()
            return result

    async def run_second() -> object:
        await started.wait()
        async with second.engine_session() as s:
            try:
                result = await second.work(s)
            except HTTPException as exc:
                await s.rollback()
                return exc
            await s.commit()
            return result

    t1 = asyncio.create_task(run_first())
    t2 = asyncio.create_task(run_second())
    await started.wait()
    await asyncio.sleep(0.5)
    release.set()
    return await asyncio.gather(t1, t2)


class _Job:
    def __init__(self, engine: AsyncEngine, work) -> None:
        self._engine = engine
        self.work = work

    def engine_session(self) -> AsyncSession:
        return AsyncSession(self._engine, expire_on_commit=False)


@pytest.mark.asyncio(loop_scope="session")
async def test_two_admins_removing_each_other_leave_one_admin(
    engine: AsyncEngine, two_admins: tuple[User, User]
) -> None:
    a, b = two_admins

    async def remove_admin_from(
        session: AsyncSession, caller: User, target: User
    ) -> User:
        return await change_user_roles(
            session, caller=caller, user_id=target.id, role_names={"visitor"}
        )

    r1, r2 = await _run_overlapping(
        _Job(engine, lambda s: remove_admin_from(s, a, b)),
        _Job(engine, lambda s: remove_admin_from(s, b, a)),
    )

    assert isinstance(r1, User)
    assert isinstance(r2, HTTPException) and r2.status_code == 409
    assert await _active_admin_ids(engine) == {a.id}


@pytest.mark.asyncio(loop_scope="session")
async def test_role_removal_and_deactivation_leave_one_admin(
    engine: AsyncEngine, two_admins: tuple[User, User]
) -> None:
    a, b = two_admins

    async def demote_b(session: AsyncSession) -> User:
        return await change_user_roles(
            session, caller=a, user_id=b.id, role_names={"visitor"}
        )

    async def deactivate_a(session: AsyncSession) -> None:
        # What PATCH does when it suspends someone.
        user = await session.get(User, a.id)
        assert user is not None
        await ensure_not_last_active_admin(session, user)
        user.is_active = False
        await session.flush()

    r1, r2 = await _run_overlapping(_Job(engine, demote_b), _Job(engine, deactivate_a))

    assert isinstance(r1, User)
    assert isinstance(r2, HTTPException) and r2.status_code == 409
    assert await _active_admin_ids(engine) == {a.id}


@pytest.mark.asyncio(loop_scope="session")
async def test_double_submitted_put_adds_each_role_once(
    engine: AsyncEngine, two_admins: tuple[User, User]
) -> None:
    a, _ = two_admins
    tag = uuid.uuid4().hex[:8]
    async with AsyncSession(engine, expire_on_commit=False) as s:
        bob = User(id=uuid.uuid4(), email=f"bob-{tag}@race.test")
        s.add(bob)
        await s.commit()
    try:

        async def make_admin(session: AsyncSession) -> User:
            return await change_user_roles(
                session, caller=a, user_id=bob.id, role_names={"visitor", "admin"}
            )

        await _run_overlapping(_Job(engine, make_admin), _Job(engine, make_admin))

        async with AsyncSession(engine) as s:
            rows = (
                (
                    await s.execute(
                        select(Role.name)
                        .join(UserRole)
                        .where(UserRole.user_id == bob.id)
                    )
                )
                .scalars()
                .all()
            )
        assert sorted(rows) == ["admin", "visitor"]

        # A later removal of admin takes effect.
        async with AsyncSession(engine, expire_on_commit=False) as s:
            await change_user_roles(s, caller=a, user_id=bob.id, role_names={"visitor"})
            await s.commit()
        async with AsyncSession(engine) as s:
            rows = (
                (
                    await s.execute(
                        select(Role.name)
                        .join(UserRole)
                        .where(UserRole.user_id == bob.id)
                    )
                )
                .scalars()
                .all()
            )
        assert rows == ["visitor"]
    finally:
        async with AsyncSession(engine) as s:
            await s.execute(delete(UserRole).where(UserRole.user_id == bob.id))
            await s.execute(delete(User).where(User.id == bob.id))
            await s.commit()
