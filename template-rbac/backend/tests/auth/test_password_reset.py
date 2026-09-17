"""Coverage for the password reset flow (#17): forgot-password must not
leak account existence, and reset tokens must be single-use, expiring,
and safe to redeem concurrently.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.repository import (
    create_password_reset_token,
    find_user_by_email,
)
from kalekit.auth.service import (
    generate_verification_token,
    hash_verification_token,
    password_reset_token_expiry,
    verify_password,
)
from kalekit.models.password_reset_token import PasswordResetToken


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_returns_202_for_a_known_email(
    client: AsyncClient, register
) -> None:
    await register("forgot-known@example.com")

    response = await client.post(
        "/v1/auth/password/forgot", json={"email": "forgot-known@example.com"}
    )

    assert response.status_code == 202


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_returns_identical_response_for_unknown_email(
    client: AsyncClient, register
) -> None:
    """Enumeration resistance: an unknown email must get the exact same
    status and body a real one gets."""
    known = await register("forgot-enum-known@example.com")
    assert known.status_code == 201

    known_response = await client.post(
        "/v1/auth/password/forgot", json={"email": "forgot-enum-known@example.com"}
    )
    unknown_response = await client.post(
        "/v1/auth/password/forgot", json={"email": "forgot-enum-unknown@example.com"}
    )

    assert known_response.status_code == unknown_response.status_code == 202
    assert known_response.json() == unknown_response.json()


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_issues_a_working_token(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("forgot-issues@example.com", "old-password123")

    response = await client.post(
        "/v1/auth/password/forgot", json={"email": "forgot-issues@example.com"}
    )
    assert response.status_code == 202

    user = await find_user_by_email(session, "forgot-issues@example.com")
    assert user is not None
    result = await session.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
    )
    tokens = result.scalars().all()
    assert len(tokens) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_invalidates_previous_tokens(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("forgot-invalidate@example.com", "old-password123")
    user = await find_user_by_email(session, "forgot-invalidate@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    first_token = await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )

    response = await client.post(
        "/v1/auth/password/forgot", json={"email": "forgot-invalidate@example.com"}
    )
    assert response.status_code == 202

    await session.refresh(first_token)
    assert first_token.used_at is not None

    reset_response = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "new-password123"},
    )
    assert reset_response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_does_not_send_for_deactivated_account(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("forgot-deactivated@example.com", "old-password123")
    user = await find_user_by_email(session, "forgot-deactivated@example.com")
    assert user is not None
    user.is_active = False
    await session.flush()

    response = await client.post(
        "/v1/auth/password/forgot", json={"email": "forgot-deactivated@example.com"}
    )
    assert response.status_code == 202

    result = await session.execute(
        select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
    )
    assert result.scalars().first() is None


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_with_valid_token_sets_new_password(
    client: AsyncClient, register, login, session: AsyncSession
) -> None:
    await register("reset-valid@example.com", "old-password123")
    user = await find_user_by_email(session, "reset-valid@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )

    response = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "new-password123"},
    )

    assert response.status_code == 200
    await session.refresh(user)
    assert user.password_hash is not None
    assert verify_password("new-password123", user.password_hash)
    assert not verify_password("old-password123", user.password_hash)

    # The new password now works at login.
    await login("reset-valid@example.com", "new-password123")


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_rejects_unknown_token(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/password/reset",
        json={"token": "not-a-real-token", "new_password": "new-password123"},
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_token_is_single_use(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("reset-single-use@example.com", "old-password123")
    user = await find_user_by_email(session, "reset-single-use@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )

    first = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "new-password123"},
    )
    second = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "another-password123"},
    )

    assert first.status_code == 200
    assert second.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_rejects_expired_token(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("reset-expired@example.com", "old-password123")
    user = await find_user_by_email(session, "reset-expired@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )

    response = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "new-password123"},
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_revokes_existing_sessions(
    client: AsyncClient, register, login, session: AsyncSession
) -> None:
    await register("reset-revokes@example.com", "old-password123")
    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "reset-revokes@example.com", "password": "old-password123"},
    )
    assert login_response.status_code == 200
    refresh_token = login_response.json()["refresh_token"]
    access_token = login_response.json()["access_token"]

    user = await find_user_by_email(session, "reset-revokes@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )

    reset_response = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "new-password123"},
    )
    assert reset_response.status_code == 200

    # The old refresh token no longer works.
    refresh_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 401

    # The old access token no longer authenticates either -- it was
    # blanket-blocked, not just left to expire naturally.
    me_response = await client.get(
        "/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me_response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_lets_an_oauth_only_user_set_a_password(
    client: AsyncClient, session: AsyncSession
) -> None:
    """OAuth-only accounts (`password_hash` is null) can use reset to
    *set* a password for the first time, linking password login onto
    the account -- #17's explicit acceptance criterion."""
    from kalekit.auth.seed import assign_role, ensure_default_roles
    from kalekit.models.user import User

    user = User(
        id=uuid.uuid4(),
        email="oauth-only@example.com",
        password_hash=None,
        email_verified=True,
    )
    session.add(user)
    await session.flush()
    visitor_role, _ = await ensure_default_roles(session)
    await assign_role(session, user, visitor_role)

    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )

    response = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "brand-new-password123"},
    )

    assert response.status_code == 200
    await session.refresh(user)
    assert user.password_hash is not None
    assert verify_password("brand-new-password123", user.password_hash)

    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "oauth-only@example.com", "password": "brand-new-password123"},
    )
    assert login_response.status_code == 200


async def _reset_with_own_session(
    engine: AsyncEngine, raw_token: str, new_password: str
) -> Response:
    """Issue one /auth/password/reset call over its own dedicated
    AsyncSession/connection and its own app instance -- mirrors
    `_register_with_own_session` in test_register_concurrency.py, so two
    "concurrent" redemptions of the same token actually race at the
    database level instead of serializing on one shared connection."""
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
            "/v1/auth/password/reset",
            json={"token": raw_token, "new_password": new_password},
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_reset_of_the_same_token_only_one_succeeds(
    engine: AsyncEngine,
) -> None:
    """Two coroutines racing `POST /auth/password/reset` with the same
    raw token, each on its own DB connection, must resolve to exactly
    one 200 and one clean 400 -- never two 200s. `claim_password_reset_token`
    exists specifically so the check-and-consume is one atomic UPDATE
    rather than a SELECT followed by a separate UPDATE, which is what
    makes this race resolve cleanly instead of both requests reading the
    token as still valid."""
    from kalekit.auth.seed import assign_role, ensure_default_roles
    from kalekit.models.user import User

    email = f"reset-race-{uuid.uuid4().hex}@example.com"
    raw_token = generate_verification_token()

    async with AsyncSession(engine, expire_on_commit=False) as setup_session:
        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=None,
            email_verified=True,
        )
        setup_session.add(user)
        await setup_session.flush()
        visitor_role, _ = await ensure_default_roles(setup_session)
        await assign_role(setup_session, user, visitor_role)
        await create_password_reset_token(
            setup_session,
            user_id=user.id,
            token_hash=hash_verification_token(raw_token),
            expires_at=password_reset_token_expiry(),
        )
        await setup_session.commit()
        user_id = user.id

    barrier = asyncio.Barrier(2)

    async def reset(new_password: str) -> Response:
        await barrier.wait()
        return await _reset_with_own_session(engine, raw_token, new_password)

    try:
        response_a, response_b = await asyncio.gather(
            reset("racer-a-password123"), reset("racer-b-password123")
        )
        statuses = sorted([response_a.status_code, response_b.status_code])

        assert statuses == [200, 400], (
            f"expected exactly one 200 and one 400, got {statuses} "
            f"(bodies: {response_a.text!r}, {response_b.text!r})"
        )
    finally:
        from sqlalchemy import delete

        from kalekit.models.password_reset_token import PasswordResetToken
        from kalekit.models.refresh_token import RefreshToken
        from kalekit.models.role import UserRole

        async with AsyncSession(engine) as cleanup_session:
            await cleanup_session.execute(
                delete(UserRole).where(UserRole.user_id == user_id)
            )
            await cleanup_session.execute(
                delete(RefreshToken).where(RefreshToken.user_id == user_id)
            )
            await cleanup_session.execute(
                delete(PasswordResetToken).where(
                    PasswordResetToken.user_id == user_id
                )
            )
            await cleanup_session.execute(
                delete(User).where(User.id == user_id)
            )
            await cleanup_session.commit()
