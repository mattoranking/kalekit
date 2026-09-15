import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_revokes_the_access_token_immediately(
    client: AsyncClient, register, login, auth_header
) -> None:
    """A token's natural expiry (ACCESS_TOKEN_EXPIRE_MINUTES) is minutes
    away -- logout has to invalidate it right now, not eventually."""
    await register("admin@example.com")
    token = await login("admin@example.com")

    response = await client.get("/v1/chat/", headers=auth_header(token))
    assert response.status_code == 200

    response = await client.post("/v1/auth/logout", headers=auth_header(token))
    assert response.status_code == 204

    response = await client.get("/v1/chat/", headers=auth_header(token))
    assert response.status_code == 401
