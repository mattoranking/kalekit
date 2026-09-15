from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)

from kalekit.config import settings
from kalekit.utils.db.models import Model


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
