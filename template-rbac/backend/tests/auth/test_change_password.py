import pytest
from httpx import AsyncClient


async def _login_pair(
    client: AsyncClient, email: str, password: str = "password123"
) -> tuple[str, str]:
    """Register + login, returning (access_token, refresh_token)."""
    await client.post(
        "/v1/auth/register",
        json={"email": email, "password": password},
    )
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_rejects_wrong_current_password(
    client: AsyncClient,
) -> None:
    access_token, _ = await _login_pair(client, "change-pw-wrong@example.com")

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "not-it", "new_password": "newpassword456"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_allows_login_with_the_new_password(
    client: AsyncClient,
) -> None:
    email = "change-pw-login@example.com"
    access_token, _ = await _login_pair(client, email)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "password123", "new_password": "newpassword456"},
    )
    assert response.status_code == 200

    old_password_login = await client.post(
        "/v1/auth/login", json={"email": email, "password": "password123"}
    )
    assert old_password_login.status_code == 401

    new_password_login = await client.post(
        "/v1/auth/login", json={"email": email, "password": "newpassword456"}
    )
    assert new_password_login.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_revokes_other_sessions_but_keeps_the_current_one(
    client: AsyncClient,
) -> None:
    email = "change-pw-sessions@example.com"
    current_access, current_refresh = await _login_pair(client, email)
    other_access, other_refresh = await _login_pair(client, email)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(current_access),
        json={"current_password": "password123", "new_password": "newpassword456"},
    )
    assert response.status_code == 200

    # The session the change was made from keeps working.
    current_refresh_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": current_refresh}
    )
    assert current_refresh_response.status_code == 200

    still_ok = await client.get("/v1/auth/me", headers=_auth(current_access))
    assert still_ok.status_code == 200

    # The other session is dead: its refresh token is revoked...
    other_refresh_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": other_refresh}
    )
    assert other_refresh_response.status_code == 401

    # ...and its still-unexpired access token stops working immediately,
    # rather than lingering until ACCESS_TOKEN_EXPIRE_MINUTES passes.
    other_me_response = await client.get("/v1/auth/me", headers=_auth(other_access))
    assert other_me_response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_requires_authentication(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/change-password",
        json={"current_password": "password123", "new_password": "newpassword456"},
    )
    assert response.status_code in (401, 403)
