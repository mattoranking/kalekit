import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_me_exposes_organization_ids(
    client, register, login, auth_header
) -> None:
    """/auth/me must return enough to build a resource URL: an id, not just
    a name (names aren't unique and every resource route is keyed by
    organization_id)."""
    register_response = await register("alice@example.com")
    registered_org = register_response.json()["organizations"][0]
    token = await login("alice@example.com")

    response = await client.get("/v1/auth/me", headers=auth_header(token))

    assert response.status_code == 200
    organizations = response.json()["organizations"]
    assert len(organizations) == 1
    assert organizations[0]["id"] == registered_org["id"]
    assert organizations[0]["name"] == registered_org["name"]
