from collections.abc import AsyncGenerator
from typing import Callable, Coroutine

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)

from kalekit.config import settings
from kalekit.models import Model  # noqa: F401 -- registers all models
from kalekit.models.organization import Organization, OrganizationMember
from kalekit.models.user import User


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


@pytest.fixture
def auth_header() -> Callable[[str], dict[str, str]]:
    """auth_header(token) -> {"Authorization": "Bearer <token>"}"""

    def _auth_header(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    return _auth_header


@pytest_asyncio.fixture(loop_scope="session")
async def org_id_for(
    session: AsyncSession,
) -> Callable[[str], Coroutine[None, None, str]]:
    """org_id_for(email) -> str(organization_id) of that user's (first) org.

    No endpoint returns a user's own organization id (only its name, via
    /auth/me) -- tests reach into the same session/transaction the app
    is using to look it up directly.
    """

    async def _org_id_for(email: str) -> str:
        result = await session.execute(
            select(Organization.id)
            .join(
                OrganizationMember,
                OrganizationMember.organization_id == Organization.id,
            )
            .join(User, User.id == OrganizationMember.user_id)
            .where(User.email == email)
        )
        return str(result.scalar_one())

    return _org_id_for
