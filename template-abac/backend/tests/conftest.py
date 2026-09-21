import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
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
from kalekit.organization.repository import create_invitation
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)


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

    The session runs inside an outer transaction and each commit becomes
    a savepoint release, so the endpoints that commit on purpose (the
    refresh revoke, #112) do not leak rows into later tests; the outer
    rollback removes everything.
    """
    async with engine.connect() as conn:
        outer = await conn.begin()
        async with AsyncSession(
            bind=conn,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ) as session:
            yield session
        await outer.rollback()


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
    """register(email, password="password12345", **extra) -> the raw response.

    Left as a raw response (not asserted) so tests can check status codes
    that aren't 201 too, e.g. a duplicate-email 409.
    """

    async def _register(
        email: str, password: str = "password12345", **extra: object
    ) -> Response:
        return await client.post(
            "/v1/auth/register",
            json={"email": email, "password": password, **extra},
        )

    return _register


@pytest_asyncio.fixture(loop_scope="session")
async def login(client: AsyncClient) -> Callable[..., Coroutine[None, None, str]]:
    """login(email, password="password12345") -> access token. Asserts success."""

    async def _login(email: str, password: str = "password12345") -> str:
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


@pytest_asyncio.fixture(loop_scope="session")
async def add_member(
    client: AsyncClient,
    session: AsyncSession,
    auth_header: Callable[[str], dict[str, str]],
) -> Callable[..., Coroutine[None, None, None]]:
    """add_member(organization_id, invitee_token, invitee_email) -> None.

    Gets `invitee_email` into `organization_id` via the real invitation
    flow: creates the invitation row directly (bypassing the invite
    endpoint's email delivery, which tests have no way to intercept
    since only the token's hash is ever persisted -- mirrors how RBAC's
    tests construct `EmailVerificationToken` rows directly) and accepts
    it through the actual `/v1/invitations/accept` endpoint, using the
    organization's own creator as the recorded inviter.
    """

    async def _add_member(
        organization_id: str, invitee_token: str, invitee_email: str
    ) -> None:
        organization = await session.get(Organization, uuid.UUID(organization_id))
        assert organization is not None
        raw_token = generate_invitation_token()
        await create_invitation(
            session,
            organization_id=organization.id,
            email=invitee_email.lower(),
            token_hash=hash_invitation_token(raw_token),
            invited_by=organization.created_by,
            expires_at=invitation_token_expiry(),
        )
        response = await client.post(
            "/v1/invitations/accept",
            json={"token": raw_token},
            headers=auth_header(invitee_token),
        )
        assert response.status_code == 201, response.text

    return _add_member


@dataclass
class TwoTenants:
    """Two distinct users, each the sole member of their own organization.

    The cross-tenant test helper: every org-scoped endpoint should get a
    test that logs in as `token_b` and hits a URL scoped to `org_a`,
    asserting a 404 and that nothing leaked/changed.
    """

    token_a: str
    org_a: str
    token_b: str
    org_b: str


@pytest_asyncio.fixture(loop_scope="session")
async def two_tenants(
    register: Callable[..., Coroutine[None, None, Response]],
    login: Callable[..., Coroutine[None, None, str]],
) -> TwoTenants:
    """Registers two users in two separate organizations.

    Use this instead of hand-rolling two `register`/`login` calls for any
    test asserting cross-tenant denial: "member of org A calling org B's
    URL gets 404 and no rows."
    """
    response_a = await register("tenant-a@example.com")
    response_b = await register("tenant-b@example.com")
    token_a = await login("tenant-a@example.com")
    token_b = await login("tenant-b@example.com")
    return TwoTenants(
        token_a=token_a,
        org_a=response_a.json()["organizations"][0]["id"],
        token_b=token_b,
        org_b=response_b.json()["organizations"][0]["id"],
    )
