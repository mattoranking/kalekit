import asyncio
import uuid
from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.models.email_verification_token import EmailVerificationToken
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.role import UserRole
from kalekit.models.user import User


async def _register_with_own_session(
    engine: AsyncEngine, email: str, password: str = "password12345"
) -> Response:
    """Issue one /auth/register call over its own dedicated AsyncSession
    (its own DB connection) and its own FastAPI app instance, mirroring
    how two independent, simultaneous production requests would each get
    their own per-request session from `AsyncSessionMiddleware`.

    Using the shared `client`/`session` fixtures from conftest would defeat
    the point of this test: they wire every request in a test to the *same*
    `AsyncSession`, so two "concurrent" calls through them are actually
    serialized on one connection and can never race at the database level.
    """
    from kalekit.main import create_app
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

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(
            "/v1/auth/register", json={"email": email, "password": password}
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_registration_same_email_only_one_succeeds(
    engine: AsyncEngine,
) -> None:
    """Two coroutines racing `POST /auth/register` with the *same* email,
    each holding its own DB connection, must resolve to exactly one 201
    and one clean 409 -- never two 201s (duplicate users) and never an
    unhandled 500 from the loser's `User.email` unique-constraint hit.

    A barrier pins both requests to the same instant right before they
    call the endpoint, so both are guaranteed to run their
    `find_user_by_email` existence check while the email is still unclaimed
    -- the exact interleaving a purely-sequential "register, then register
    the duplicate again" test can never exercise, and the one the bug
    report explicitly calls out as needed.
    """
    email = f"race-{uuid.uuid4().hex}@example.com"
    barrier = asyncio.Barrier(2)

    async def register() -> Response:
        await barrier.wait()
        return await _register_with_own_session(engine, email)

    try:
        response_a, response_b = await asyncio.gather(register(), register())
        statuses = sorted([response_a.status_code, response_b.status_code])

        assert statuses == [201, 409], (
            f"expected exactly one 201 and one 409, got {statuses} "
            f"(bodies: {response_a.text!r}, {response_b.text!r})"
        )
    finally:
        async with AsyncSession(engine) as cleanup_session:
            user = (
                await cleanup_session.execute(
                    select(User).where(User.email == email)
                )
            ).scalar_one_or_none()
            if user is not None:
                await cleanup_session.execute(
                    delete(UserRole).where(UserRole.user_id == user.id)
                )
                await cleanup_session.execute(
                    delete(RefreshToken).where(RefreshToken.user_id == user.id)
                )
                await cleanup_session.execute(
                    delete(EmailVerificationToken).where(
                        EmailVerificationToken.user_id == user.id
                    )
                )
                await cleanup_session.execute(
                    delete(User).where(User.id == user.id)
                )
            await cleanup_session.commit()
