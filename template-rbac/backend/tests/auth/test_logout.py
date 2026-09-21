import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_revokes_the_access_token_immediately(
    client: AsyncClient, register, auth_header, promote_to_admin
) -> None:
    """A token's natural expiry (ACCESS_TOKEN_EXPIRE_MINUTES) is minutes
    away -- logout has to invalidate it right now, not eventually."""
    await register("admin@example.com")
    await promote_to_admin("admin@example.com")
    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "admin@example.com", "password": "password12345"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    refresh_token = login_response.json()["refresh_token"]

    response = await client.get("/v1/chat/", headers=auth_header(token))
    assert response.status_code == 200

    response = await client.post(
        "/v1/auth/logout",
        headers=auth_header(token),
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 204

    response = await client.get("/v1/chat/", headers=auth_header(token))
    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_requires_a_refresh_token(
    client: AsyncClient, register, auth_header
) -> None:
    """No refresh token means no way to know which session to end --
    the request is rejected rather than silently ending only "half"
    of the session (access token blocked, refresh token left alive)."""
    await register("no-body@example.com")
    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "no-body@example.com", "password": "password12345"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    response = await client.post("/v1/auth/logout", headers=auth_header(token))
    assert response.status_code == 422
