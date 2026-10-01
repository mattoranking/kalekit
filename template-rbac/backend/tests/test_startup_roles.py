"""Roles are reconciled from roles.yaml when the app starts (#242).

The shared `client` fixture never runs the lifespan (ASGITransport does
not send lifespan events), so these tests enter `lifespan(app)` by hand.
The lifespan opens its own engine and commits for real, so the tests
commit their setup rows too and remove everything they created.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
import pytest_asyncio
import redis.asyncio as redis
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.permissions import get_permissions_for_roles, get_redis
from kalekit.auth.repository import create_user
from kalekit.auth.scope import SCOPES_SUPPORTED
from kalekit.auth.seed import ADMIN_ROLE, VISITOR_ROLE
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.role import Permission, Role, RolePermission, UserRole
from kalekit.models.user import User

OLD_ADMIN_SCOPES = [s for s in SCOPES_SUPPORTED if not s.startswith("roles:")]
PASSWORD = "password12345"


async def _delete_default_roles(engine: AsyncEngine) -> None:
    async with AsyncSession(engine) as s:
        ids = (
            (
                await s.execute(
                    select(Role.id).where(Role.name.in_([VISITOR_ROLE, ADMIN_ROLE]))
                )
            )
            .scalars()
            .all()
        )
        await s.execute(delete(UserRole).where(UserRole.role_id.in_(ids)))
        await s.execute(delete(RolePermission).where(RolePermission.role_id.in_(ids)))
        await s.execute(delete(Role).where(Role.id.in_(ids)))
        await s.execute(
            delete(Permission).where(Permission.name.in_(list(SCOPES_SUPPORTED)))
        )
        await s.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def old_database(engine: AsyncEngine) -> AsyncGenerator[str]:
    """A database seeded by an older roles.yaml: the admin role holds every
    scope except roles:read and roles:write, and one admin user exists.
    Yields the admin's email."""
    await _delete_default_roles(engine)
    email = f"old-admin-{uuid.uuid4().hex[:8]}@startup.test"
    async with AsyncSession(engine, expire_on_commit=False) as s:
        visitor = Role(id=uuid.uuid4(), name=VISITOR_ROLE, description="old")
        admin = Role(id=uuid.uuid4(), name=ADMIN_ROLE, description="Full access")
        s.add_all([visitor, admin])
        await s.flush()
        for scope in OLD_ADMIN_SCOPES:
            permission = Permission(id=uuid.uuid4(), name=scope)
            s.add(permission)
            await s.flush()
            s.add(RolePermission(role_id=admin.id, permission_id=permission.id))
        user = await create_user(s, email, PASSWORD, email_verified=True)
        s.add(UserRole(user_id=user.id, role_id=admin.id))
        await s.commit()
    try:
        yield email
    finally:
        async with AsyncSession(engine) as s:
            user_id = (
                await s.execute(select(User.id).where(User.email == email))
            ).scalar_one()
            await s.execute(delete(RefreshToken).where(RefreshToken.user_id == user_id))
            await s.execute(delete(UserRole).where(UserRole.user_id == user_id))
            await s.execute(delete(User).where(User.id == user_id))
            await s.commit()
        await _delete_default_roles(engine)


@asynccontextmanager
async def _running_app(engine: AsyncEngine) -> AsyncIterator[AsyncClient]:
    """The real app with its lifespan entered, serving requests on fresh
    committing sessions."""
    from kalekit.main import create_app, lifespan
    from kalekit.postgres import get_db_read_session, get_db_session

    app = create_app()

    async def _session() -> AsyncGenerator[AsyncSession]:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[get_db_read_session] = _session

    async with lifespan(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client


async def _admin_gets_roles(client: AsyncClient, email: str) -> int:
    login = await client.post(
        "/v1/auth/login",
        json={"email": email, "password": PASSWORD, "client": "admin"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    response = await client.get(
        "/v1/roles", headers={"Authorization": f"Bearer {token}"}
    )
    return response.status_code


async def _admin_permissions(engine: AsyncEngine) -> list[str]:
    async with AsyncSession(engine) as s:
        return sorted(
            (
                await s.execute(
                    select(Permission.name)
                    .join(RolePermission)
                    .join(Role)
                    .where(Role.name == ADMIN_ROLE)
                )
            )
            .scalars()
            .all()
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_startup_gives_an_old_database_admin_the_new_scopes(
    engine: AsyncEngine, old_database: str
) -> None:
    # An instance of the old version already cached the admin role's
    # permissions, so a reconcile that leaves Redis alone would still
    # serve the old set.
    async with AsyncSession(engine) as s:
        before = await get_permissions_for_roles(s, [ADMIN_ROLE])
    assert "roles:read" not in before
    assert await (await get_redis()).exists(f"role:{ADMIN_ROLE}:permissions")

    async with _running_app(engine) as client:
        assert await _admin_gets_roles(client, old_database) == 200

    assert await _admin_permissions(engine) == sorted(SCOPES_SUPPORTED)


@pytest.mark.asyncio(loop_scope="session")
async def test_startup_succeeds_and_still_reconciles_when_redis_is_down(
    engine: AsyncEngine, old_database: str
) -> None:
    dead = redis.from_url(
        "redis://127.0.0.1:1/3",
        socket_connect_timeout=0.2,
        socket_timeout=0.2,
    )

    async def _dead_redis() -> redis.Redis:
        return dead

    from kalekit.main import create_app, lifespan

    with patch("kalekit.auth.permissions.get_redis", _dead_redis):
        async with lifespan(create_app()):
            pass

    assert await _admin_permissions(engine) == sorted(SCOPES_SUPPORTED)


@pytest.mark.asyncio(loop_scope="session")
async def test_two_startups_at_once_do_not_fail_or_duplicate(
    engine: AsyncEngine,
) -> None:
    """Both instances start against an empty database and race to seed it."""
    from kalekit.main import create_app, lifespan

    await _delete_default_roles(engine)
    try:

        async def start() -> None:
            async with lifespan(create_app()):
                pass

        await asyncio.gather(start(), start())

        async with AsyncSession(engine) as s:
            roles = (
                (
                    await s.execute(
                        select(Role.name).where(
                            Role.name.in_([VISITOR_ROLE, ADMIN_ROLE])
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert sorted(roles) == [ADMIN_ROLE, VISITOR_ROLE]
        assert await _admin_permissions(engine) == sorted(SCOPES_SUPPORTED)
    finally:
        await _delete_default_roles(engine)
