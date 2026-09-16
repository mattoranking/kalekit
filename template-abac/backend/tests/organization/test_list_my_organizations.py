import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_get_organizations_lists_only_the_callers_memberships(
    client, register, login, auth_header
) -> None:
    alice_register = await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")

    response = await client.get("/v1/organizations", headers=auth_header(token_alice))

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == alice_register.json()["organizations"][0]["id"]
    assert items[0]["name"] == "alice's workspace"


@pytest.mark.asyncio(loop_scope="session")
async def test_get_organizations_requires_authentication(client) -> None:
    response = await client.get("/v1/organizations")

    assert response.status_code in (401, 403)
