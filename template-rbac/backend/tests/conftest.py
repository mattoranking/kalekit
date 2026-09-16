from collections.abc import AsyncGenerator
from typing import Callable, Coroutine

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)

from kalekit.auth.repository import find_user_by_email
from kalekit.auth.seed import assign_role, ensure_default_roles
from kalekit.config import settings
from kalekit.models import Model  # noqa: F401 -- registers all models


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def clear_redis() -> AsyncGenerator[None]:
    """Redis isn't part of the per-test Postgres rollback below, so a
    role's cached permissions from an earlier (rolled-back) test can
    leak into a later test that reuses the same role name. Flush it
    before every test so role/permission tests don't become
    order-dependent on what ran before them.
    """
    from kalekit.auth.permissions import get_redis

    redis = await get_redis()
    await redis.flushdb()
    yield


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def engine() -> AsyncGenerator[AsyncEngine]:
    """Create a test database engine (once per test session)."""
    engine = create_async_engine(
        str(settings.get_postgres_dsn("asyncpg")),
        echo=False,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Model.metadata.create_all)

    yield engine

    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Model.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="session")
async def session(engine: AsyncEngine) -> AsyncGenerator[AsyncSession]:
    """
    Provide a session that is rolled back after each test for isolation.

    The dependency overrides never commit, so rollback cleanly
    removes all flushed-but-uncommitted test data.
    """
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(loop_scope="session")
async def client(
    session: AsyncSession,
) -> AsyncGenerator[AsyncClient]:
    """
    Provide an HTTP test client with FastAPI dependency overrides
    so both read and write endpoints use the test transaction session.
    """
    from kalekit.main import create_app
    from kalekit.postgres import get_db_read_session, get_db_session

    app = create_app()

    async def _override_db_session() -> AsyncGenerator[AsyncSession]:
        yield session

    async def _override_db_read_session() -> AsyncGenerator[AsyncSession]:
        yield session

    app.dependency_overrides[get_db_session] = _override_db_session
    app.dependency_overrides[get_db_read_session] = _override_db_read_session

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=True,
    ) as ac:
        yield ac


@pytest_asyncio.fixture(loop_scope="session")
async def register(
    client: AsyncClient,
) -> Callable[..., Coroutine[None, None, Response]]:
    """register(email, password="password123", **extra) -> the raw response.

    Left as a raw response (not asserted) so tests can check status codes
    that aren't 201 too, e.g. a duplicate-email 409.
    """

    async def _register(
        email: str, password: str = "password123", **extra: object
    ) -> Response:
        return await client.post(
            "/v1/auth/register",
            json={"email": email, "password": password, **extra},
        )

    return _register


@pytest_asyncio.fixture(loop_scope="session")
async def login(client: AsyncClient) -> Callable[..., Coroutine[None, None, str]]:
    """login(email, password="password123") -> access token. Asserts success."""

    async def _login(email: str, password: str = "password123") -> str:
        response = await client.post(
            "/v1/auth/login", json={"email": email, "password": password}
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]

    return _login


@pytest_asyncio.fixture(loop_scope="session")
async def promote_to_admin(
    session: AsyncSession,
) -> Callable[[str], Coroutine[None, None, None]]:
    """promote_to_admin(email) -- grant the admin role to an already
    registered user, inside the same test transaction.

    There is no first-user-becomes-admin shortcut anymore (see
    kalekit/cli.py, the real out-of-band way to mint an admin) so tests
    that need an admin user have to grant the role explicitly.
    """

    async def _promote_to_admin(email: str) -> None:
        user = await find_user_by_email(session, email)
        assert user is not None, f"no user registered with email {email!r}"
        _, admin_role = await ensure_default_roles(session)
        await assign_role(session, user, admin_role)

    return _promote_to_admin


@pytest.fixture
def auth_header() -> Callable[[str], dict[str, str]]:
    """auth_header(token) -> {"Authorization": "Bearer <token>"}"""

    def _auth_header(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    return _auth_header
