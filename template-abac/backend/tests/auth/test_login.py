from collections.abc import Coroutine
from typing import Callable

import pytest
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.oauth.repository import find_or_create_oauth_user


@pytest.mark.asyncio(loop_scope="session")
async def test_login_succeeds_with_correct_password(
    register: Callable[..., Coroutine[None, None, Response]],
    login: Callable[..., Coroutine[None, None, str]],
) -> None:
    await register("alice@example.com", password="password12345")

    token = await login("alice@example.com", password="password12345")

    assert token


@pytest.mark.asyncio(loop_scope="session")
async def test_login_rejects_wrong_password(
    register: Callable[..., Coroutine[None, None, Response]],
    client: AsyncClient,
) -> None:
    await register("bob@example.com", password="password12345")

    response = await client.post(
        "/v1/auth/login",
        json={"email": "bob@example.com", "password": "wrong-password"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_login_rejects_unknown_email(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.com", "password": "password12345"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_login_against_oauth_only_account_returns_401_not_500(
    session: AsyncSession,
    client: AsyncClient,
) -> None:
    """OAuth-only users are created with password_hash=None. Attempting a
    password login against their email must return a clean 401, not crash
    passlib's CryptContext.verify() with a 500."""
    await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="oauth-only-1",
        account_email="oauth-only@example.com",
    )

    response = await client.post(
        "/v1/auth/login",
        json={"email": "oauth-only@example.com", "password": "any-password"},
    )

    assert response.status_code == 401
