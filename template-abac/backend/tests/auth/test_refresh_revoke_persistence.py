"""The family revoke in /auth/refresh must survive the 401 that follows it.

`refresh()` revokes a token family on reuse detection and then raises
HTTPException(401).
The real `get_db_session` rolls back on any exception, so without an
explicit commit before the raise the revoke is undone and a
detected-stolen session's refresh tokens stay active in the database.
The shared `client` fixture overrides the session dependency with one
that never rolls back or commits, so it cannot see this. These tests run
through the real `get_db_session` and the real `AsyncSessionMiddleware`
and read the family back in a fresh session.
"""

import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.types import ASGIApp, Receive, Scope, Send

from kalekit.config import settings
from kalekit.models import Model
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.user import User
from kalekit.postgres import AsyncSessionMiddleware


@pytest_asyncio.fixture(loop_scope="session")
async def real_client(engine: AsyncEngine) -> AsyncGenerator[AsyncClient]:
    """Client with NO dependency overrides: the app's real
    `get_db_session`, fed by the real session middleware (which the app
    skips under KALEKIT_ENV=testing, so it is added here)."""
    from kalekit.main import create_app

    app = create_app()
    app.add_middleware(AsyncSessionMiddleware)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def with_state(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope["state"] = {"async_sessionmaker": sessionmaker}
        await outer(scope, receive, send)

    outer: ASGIApp = app
    async with AsyncClient(
        transport=ASGITransport(app=with_state), base_url="http://test"
    ) as ac:
        yield ac


async def _family_revoked_flags(engine: AsyncEngine, email: str) -> list[bool]:
    async with AsyncSession(engine) as fresh:
        result = await fresh.execute(
            select(RefreshToken.revoked)
            .join(User, User.id == RefreshToken.user_id)
            .where(User.email == email)
        )
        return list(result.scalars())


async def _cleanup(engine: AsyncEngine, email: str) -> None:
    async with AsyncSession(engine) as s:
        user_ids = select(User.id).where(User.email == email)
        # Every table with a foreign key to users, children first.
        for table in reversed(Model.metadata.sorted_tables):
            if table is User.__table__:
                continue
            for fk in table.foreign_keys:
                if fk.column.table is User.__table__:
                    await s.execute(delete(table).where(fk.parent.in_(user_ids)))
        await s.execute(delete(User).where(User.email == email))
        await s.commit()


async def _login(client: AsyncClient, email: str) -> str:
    await client.post(
        "/v1/auth/register", json={"email": email, "password": "password12345"}
    )
    r = await client.post(
        "/v1/auth/login", json={"email": email, "password": "password12345"}
    )
    assert r.status_code == 200, r.text
    return r.json()["refresh_token"]


@pytest.mark.asyncio(loop_scope="session")
async def test_reuse_detection_revoke_persists_through_real_session(
    real_client: AsyncClient, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "REFRESH_TOKEN_GRACE_PERIOD_SECONDS", 0)
    email = f"reuse-{uuid.uuid4().hex[:8]}@example.com"
    try:
        old = await _login(real_client, email)
        first = await real_client.post("/v1/auth/refresh", json={"refresh_token": old})
        assert first.status_code == 200

        replay = await real_client.post("/v1/auth/refresh", json={"refresh_token": old})
        assert replay.status_code == 401
        assert replay.json() == {"detail": "Refresh token already used"}

        flags = await _family_revoked_flags(engine, email)
        assert len(flags) == 2
        assert all(flags), "family revoke was rolled back by get_db_session"
    finally:
        await _cleanup(engine, email)
