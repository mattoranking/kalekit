import re
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
from kalekit.config import Environment, settings
from kalekit.models.email_verification_token import EmailVerificationToken
from kalekit.models.user import User
from kalekit.utils import email as email_module


class _RecordingSender(email_module.EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.sent.append({"to": to, "subject": subject, "body": body})

    def last_token(self) -> str:
        match = re.search(r"verify-email\?token=(\S+)", self.sent[-1]["body"])
        assert match, self.sent[-1]["body"]
        return match.group(1)


@pytest.fixture
def sender(monkeypatch: pytest.MonkeyPatch) -> _RecordingSender:
    recorder = _RecordingSender()
    monkeypatch.setattr(email_module, "get_email_sender", lambda: recorder)
    return recorder


async def _issue_token(session: AsyncSession, email: str, **kwargs) -> str:
    user = await find_user_by_email(session, email)
    assert user is not None
    raw_token = generate_verification_token()
    await create_verification_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=kwargs.get("expires_at", verification_token_expiry()),
    )
    return raw_token


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
async def test_register_emails_a_link_that_verifies_the_account(
    client: AsyncClient, register, session: AsyncSession, sender: _RecordingSender
) -> None:
    await register("link@example.com")

    assert [m["to"] for m in sender.sent] == ["link@example.com"]
    response = await client.post(
        "/v1/auth/verify-email", json={"token": sender.last_token()}
    )

    assert response.status_code == 200
    user = await find_user_by_email(session, "link@example.com")
    assert user is not None
    await session.refresh(user)
    assert user.email_verified is True


@pytest.mark.asyncio(loop_scope="session")
async def test_register_fails_before_writing_when_no_email_provider_is_configured(
    register, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ENV", Environment.production)

    with pytest.raises(RuntimeError):
        await register("no-provider@example.com")

    assert await find_user_by_email(session, "no-provider@example.com") is None


@pytest.mark.asyncio(loop_scope="session")
async def test_register_stores_only_the_hash_of_the_token(
    register, session: AsyncSession, sender: _RecordingSender
) -> None:
    await register("hashed@example.com")

    rows = (await session.execute(select(EmailVerificationToken))).scalars().all()
    assert [r.token_hash for r in rows] == [
        hash_verification_token(sender.last_token())
    ]


@pytest.mark.asyncio(loop_scope="session")
async def test_verify_email_with_valid_token_marks_user_verified(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("verify-me@example.com")
    raw_token = await _issue_token(session, "verify-me@example.com")

    response = await client.post("/v1/auth/verify-email", json={"token": raw_token})

    assert response.status_code == 200
    user = await find_user_by_email(session, "verify-me@example.com")
    assert user is not None
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
    raw_token = await _issue_token(session, "single-use@example.com")

    first = await client.post("/v1/auth/verify-email", json={"token": raw_token})
    second = await client.post("/v1/auth/verify-email", json={"token": raw_token})

    assert first.status_code == 200
    assert second.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_verify_email_rejects_expired_token(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("expired@example.com")
    raw_token = await _issue_token(
        session,
        "expired@example.com",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    response = await client.post("/v1/auth/verify-email", json={"token": raw_token})

    assert response.status_code == 400
    user = await find_user_by_email(session, "expired@example.com")
    assert user is not None and user.email_verified is False


@pytest.mark.asyncio(loop_scope="session")
async def test_me_reports_email_verified(
    client: AsyncClient, register, login, auth_header, session: AsyncSession
) -> None:
    await register("me-verified@example.com")
    token = await login("me-verified@example.com")

    before = await client.get("/v1/auth/me", headers=auth_header(token))
    user = await find_user_by_email(session, "me-verified@example.com")
    assert user is not None
    user.email_verified = True
    await session.flush()
    after = await client.get("/v1/auth/me", headers=auth_header(token))

    assert before.json()["email_verified"] is False
    assert after.json()["email_verified"] is True


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_requires_authentication(
    client: AsyncClient,
) -> None:
    response = await client.post("/v1/auth/resend-verification")

    assert response.status_code in (401, 403)


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_emails_a_working_link(
    client: AsyncClient,
    register,
    login,
    auth_header,
    sender: _RecordingSender,
) -> None:
    await register("resend@example.com")
    token = await login("resend@example.com")
    sender.sent.clear()

    response = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
    )

    assert response.status_code == 200
    assert [m["to"] for m in sender.sent] == ["resend@example.com"]
    verify = await client.post(
        "/v1/auth/verify-email", json={"token": sender.last_token()}
    )
    assert verify.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_invalidates_previous_tokens(
    client: AsyncClient,
    register,
    login,
    auth_header,
    sender: _RecordingSender,
) -> None:
    await register("resend-twice@example.com")
    token = await login("resend-twice@example.com")
    registration_token = sender.last_token()

    response = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
    )
    assert response.status_code == 200

    stale = await client.post(
        "/v1/auth/verify-email", json={"token": registration_token}
    )
    assert stale.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_for_a_verified_user_sends_nothing(
    client: AsyncClient,
    register,
    login,
    auth_header,
    session: AsyncSession,
    sender: _RecordingSender,
) -> None:
    await register("already@example.com")
    token = await login("already@example.com")
    user = await find_user_by_email(session, "already@example.com")
    assert user is not None
    user.email_verified = True
    await session.flush()
    sender.sent.clear()

    response = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
    )

    assert response.status_code == 200
    assert sender.sent == []


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_for_a_user_without_email_is_rejected(
    client: AsyncClient,
    register,
    login,
    auth_header,
    session: AsyncSession,
    sender: _RecordingSender,
) -> None:
    """ABAC users can have a NULL email (OAuth providers that return none)."""
    await register("will-lose-email@example.com")
    token = await login("will-lose-email@example.com")
    user = await find_user_by_email(session, "will-lose-email@example.com")
    assert user is not None
    user.email = None
    await session.flush()
    sender.sent.clear()

    response = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
    )

    assert response.status_code == 400
    assert sender.sent == []


@pytest.mark.asyncio(loop_scope="session")
async def test_unverified_user_can_log_in_by_default(register, login) -> None:
    await register("default-login@example.com")

    assert await login("default-login@example.com")


@pytest.mark.asyncio(loop_scope="session")
async def test_login_is_blocked_until_verified_when_setting_is_on(
    client: AsyncClient,
    register,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN", True)
    await register("gated@example.com")
    body = {"email": "gated@example.com", "password": "password12345"}

    blocked = await client.post("/v1/auth/login", json=body)
    user = await find_user_by_email(session, "gated@example.com")
    assert user is not None
    user.email_verified = True
    await session.flush()
    allowed = await client.post("/v1/auth/login", json=body)

    assert blocked.status_code == 403
    assert allowed.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_require_verified_email_dependency_gates_unverified_users() -> None:
    from fastapi import HTTPException

    from kalekit.auth.dependencies import require_verified_email

    unverified = User(email="a@example.com", email_verified=False)
    verified = User(email="b@example.com", email_verified=True)

    with pytest.raises(HTTPException) as exc:
        await require_verified_email(unverified)
    assert exc.value.status_code == 403
    assert await require_verified_email(verified) is verified
