import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.oauth.repository import find_or_create_oauth_user


@pytest.mark.asyncio(loop_scope="session")
async def test_login_against_oauth_only_account_returns_401_not_500(
    session: AsyncSession,
    client: AsyncClient,
) -> None:
    """OAuth-only users are created with password_hash=None. A password
    login against their email must return a clean 401. Argon2 hash
    verification raises on a missing hash, so the endpoint has to
    reject it before calling the hasher."""
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
