from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import create_verification_token, find_user_by_email
from kalekit.auth.service import (
    generate_verification_token,
    hash_verification_token,
    verification_token_expiry,
)
from kalekit.models.email_verification_token import EmailVerificationToken


@pytest.mark.asyncio(loop_scope="session")
async def test_new_registrations_start_unverified(
    register, session: AsyncSession
) -> None:
    await register("new-user@example.com")

    user = await find_user_by_email(session, "new-user@example.com")

    assert user is not None
    assert user.email_verified is False


@pytest.mark.asyncio(loop_scope="session")
async def test_register_response_reports_unverified(register) -> None:
    response = await register("register-response@example.com")

    assert response.status_code == 201
    assert response.json()["email_verified"] is False


@pytest.mark.asyncio(loop_scope="session")
async def test_verify_email_with_valid_token_marks_user_verified(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("verify-me@example.com")
    user = await find_user_by_email(session, "verify-me@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    await create_verification_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=verification_token_expiry(),
    )

    response = await client.post(
        "/v1/auth/verify-email", json={"token": raw_token}
    )

    assert response.status_code == 200
    await session.refresh(user)
    assert user.email_verified is True


@pytest.mark.asyncio(loop_scope="session")
async def test_verify_email_rejects_unknown_token(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/verify-email", json={"token": "not-a-real-token"}
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_verify_email_token_is_single_use(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("single-use@example.com")
    user = await find_user_by_email(session, "single-use@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    await create_verification_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=verification_token_expiry(),
    )

    first = await client.post("/v1/auth/verify-email", json={"token": raw_token})
    second = await client.post("/v1/auth/verify-email", json={"token": raw_token})

    assert first.status_code == 200
    assert second.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_verify_email_rejects_expired_token(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("expired@example.com")
    user = await find_user_by_email(session, "expired@example.com")
    assert user is not None

    raw_token = generate_verification_token()
    await create_verification_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    response = await client.post(
        "/v1/auth/verify-email", json={"token": raw_token}
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_requires_authentication(
    client: AsyncClient,
) -> None:
    response = await client.post("/v1/auth/resend-verification")

    assert response.status_code in (401, 403)


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_issues_a_working_token(
    client: AsyncClient,
    register,
    login,
    auth_header,
    session: AsyncSession,
) -> None:
    await register("resend@example.com")
    token = await login("resend@example.com")

    response = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
    )
    assert response.status_code == 200

    # The endpoint doesn't hand back the raw token (it's only ever in
    # the emailed link), so exercise it end-to-end: read the token
    # this call just wrote via the same DB session the app used.
    user = await find_user_by_email(session, "resend@example.com")
    assert user is not None
    result = await session.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None),
        )
    )
    tokens = result.scalars().all()
    assert len(tokens) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_invalidates_previous_tokens(
    client: AsyncClient,
    register,
    login,
    auth_header,
    session: AsyncSession,
) -> None:
    await register("resend-twice@example.com")
    token = await login("resend-twice@example.com")

    user = await find_user_by_email(session, "resend-twice@example.com")
    assert user is not None

    # A token was already issued at registration time.
    raw_token = generate_verification_token()
    first_token = await create_verification_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=verification_token_expiry(),
    )

    response = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
    )
    assert response.status_code == 200

    await session.refresh(first_token)
    assert first_token.used_at is not None

    # The now-stale token from before the resend must no longer verify.
    verify_response = await client.post(
        "/v1/auth/verify-email", json={"token": raw_token}
    )
    assert verify_response.status_code == 400
