"""The account pre-hijack attack from #7 / #164, driven through the real
OAuth callback endpoint.

1. Attacker registers victim@example.com with a password they control.
2. The real owner later signs in with an OAuth provider using that address.
3. Without the verified-email gate, step 2 links the owner's OAuth identity
   to the attacker's account and hands the owner a session for it.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.config import settings
from kalekit.models.oauth_account import OAuthAccount
from kalekit.models.user import User
from kalekit.oauth.endpoints import _get_provider_email_verified
from kalekit.redis import get_redis


class _FakeGoogle:
    def __init__(self, *, email: str | None, verified: bool) -> None:
        self._info = {"id": "g-1", "email": email, "verified_email": verified}

    async def exchange_code(self, code: str, code_verifier: str | None = None):
        return {"access_token": "provider-token"}

    async def get_user_info(self, access_token: str) -> dict:
        return self._info


async def _callback(client: AsyncClient, state: str):
    r = await get_redis()
    await r.set(f"oauth_state:{state}", "google", ex=60)
    return await client.get(
        "/v1/oauth/google/callback", params={"code": "c", "state": state}
    )


def _use_provider(monkeypatch: pytest.MonkeyPatch, provider: _FakeGoogle) -> None:
    monkeypatch.setattr("kalekit.oauth.endpoints._get_provider", lambda p: provider)


async def _linked_accounts(session: AsyncSession) -> list[OAuthAccount]:
    return list((await session.execute(select(OAuthAccount))).scalars())


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_refuses_to_link_to_an_unverified_password_account(
    client: AsyncClient,
    session: AsyncSession,
    register,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await register("victim@example.com", "attacker-controlled-pw")
    _use_provider(monkeypatch, _FakeGoogle(email="victim@example.com", verified=True))

    response = await _callback(client, "state-164-attack")

    assert response.status_code == 409, response.text
    assert "access_token" not in response.text
    assert await _linked_accounts(session) == []


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_refuses_to_link_when_provider_email_is_unverified(
    client: AsyncClient,
    session: AsyncSession,
    register,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await register("owner@example.com")
    user = await find_user_by_email(session, "owner@example.com")
    assert user is not None
    user.email_verified = True
    await session.flush()
    _use_provider(monkeypatch, _FakeGoogle(email="owner@example.com", verified=False))

    response = await _callback(client, "state-164-unverified-idp")

    assert response.status_code == 409, response.text
    assert await _linked_accounts(session) == []


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_links_when_both_sides_are_verified(
    client: AsyncClient,
    session: AsyncSession,
    register,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await register("legit@example.com")
    user = await find_user_by_email(session, "legit@example.com")
    assert user is not None
    user.email_verified = True
    await session.flush()
    _use_provider(monkeypatch, _FakeGoogle(email="legit@example.com", verified=True))

    response = await _callback(client, "state-164-legit")

    assert response.status_code == 200, response.text
    accounts = await _linked_accounts(session)
    assert [a.user_id for a in accounts] == [user.id]


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_with_no_provider_email_creates_a_separate_unverified_user(
    client: AsyncClient,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_provider(monkeypatch, _FakeGoogle(email=None, verified=True))

    response = await _callback(client, "state-164-null-email")

    assert response.status_code == 200, response.text
    accounts = await _linked_accounts(session)
    assert len(accounts) == 1
    user = await session.get(User, accounts[0].user_id)
    assert user is not None
    assert user.email is None
    assert user.email_verified is False


@pytest.mark.asyncio(loop_scope="session")
async def test_google_provider_verification_flag_is_read_from_userinfo() -> None:
    assert await _get_provider_email_verified(
        "google", {"verified_email": True}, "t", "a@example.com"
    )
    assert not await _get_provider_email_verified(
        "google", {"verified_email": False}, "t", "a@example.com"
    )
    assert not await _get_provider_email_verified("google", {}, "t", "a@example.com")


@pytest.mark.asyncio(loop_scope="session")
async def test_provider_without_an_email_is_never_verified() -> None:
    assert not await _get_provider_email_verified(
        "google", {"verified_email": True}, "t", None
    )
    assert not await _get_provider_email_verified("twitter", {}, "t", None)


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_blocks_unverified_new_user_when_login_requires_verification(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN", True)
    _use_provider(monkeypatch, _FakeGoogle(email="new@example.com", verified=False))

    response = await _callback(client, "state-164-gated")

    assert response.status_code == 403, response.text
    assert "access_token" not in response.text
