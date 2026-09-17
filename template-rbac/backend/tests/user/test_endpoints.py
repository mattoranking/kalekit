import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_list_users(
    client: AsyncClient, register, login, auth_header, promote_to_admin
) -> None:
    await register("admin@example.com")
    await promote_to_admin("admin@example.com")
    # /v1/users/ is an admin-client-only route (see #6) -- a web-client
    # token doesn't qualify even for a user who holds the admin role.
    token = await login("admin@example.com", client_type="admin")

    response = await client.get("/v1/users/", headers=auth_header(token))

    assert response.status_code == 200
    assert response.json()["total"] == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_role_via_web_client_cannot_list_users(
    client: AsyncClient, register, login, auth_header, promote_to_admin
) -> None:
    """An admin token minted by the *web* client must not work on an
    admin-only route just because the underlying user holds the admin
    role and its scopes include admin permissions -- the route also
    requires the token itself to have been minted by the admin client.
    See #6."""
    await register("admin-web@example.com")
    await promote_to_admin("admin-web@example.com")
    token = await login("admin-web@example.com", client_type="web")

    response = await client.get("/v1/users/", headers=auth_header(token))

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_visitor_cannot_list_users(
    client: AsyncClient, register, login, auth_header
) -> None:
    await register("admin@example.com")
    await register("visitor@example.com")
    token = await login("visitor@example.com")

    response = await client.get("/v1/users/", headers=auth_header(token))

    assert response.status_code == 403
