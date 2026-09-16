import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_list_users(
    client: AsyncClient, register, login, auth_header, promote_to_admin
) -> None:
    await register("admin@example.com")
    await promote_to_admin("admin@example.com")
    token = await login("admin@example.com")

    response = await client.get("/v1/users/", headers=auth_header(token))

    assert response.status_code == 200
    assert response.json()["total"] == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_visitor_cannot_list_users(
    client: AsyncClient, register, login, auth_header
) -> None:
    await register("admin@example.com")
    await register("visitor@example.com")
    token = await login("visitor@example.com")

    response = await client.get("/v1/users/", headers=auth_header(token))

    assert response.status_code == 403
