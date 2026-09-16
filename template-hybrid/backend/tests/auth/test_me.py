import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_me_exposes_org_id_and_role(client, register, login, auth_header) -> None:
    """/auth/me must return enough for a client to build a resource URL
    and decide which controls to show: an id (not just a name -- names
    aren't unique and routes are keyed by organization_id) and the
    caller's role in that org."""
    register_response = await register("alice@example.com")
    registered_org = register_response.json()["organizations"][0]
    token = await login("alice@example.com")

    response = await client.get("/v1/auth/me", headers=auth_header(token))

    assert response.status_code == 200
    organizations = response.json()["organizations"]
    assert len(organizations) == 1
    assert organizations[0]["id"] == registered_org["id"]
    assert organizations[0]["name"] == registered_org["name"]
    assert organizations[0]["role"] == "owner"


@pytest.mark.asyncio(loop_scope="session")
async def test_me_reports_non_owner_role(
    client, register, login, auth_header, org_id_for
) -> None:
    """A member invited at a role other than owner sees that role
    reflected back, not the inviting owner's."""
    await register("owner@example.com")
    await register("viewer@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "viewer@example.com", "role": "viewer"},
        headers=auth_header(token_owner),
    )

    token_viewer = await login("viewer@example.com")
    response = await client.get("/v1/auth/me", headers=auth_header(token_viewer))

    assert response.status_code == 200
    organizations = response.json()["organizations"]
    # The invited viewer also has their own personal workspace from
    # registration, plus the org they were invited into.
    org_entry = next(o for o in organizations if o["id"] == org)
    assert org_entry["role"] == "viewer"
