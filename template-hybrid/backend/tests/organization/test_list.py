import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_list_my_organizations_reports_role(
    client, register, login, auth_header
) -> None:
    """GET /organizations returns the caller's own memberships with the
    role held in each -- for UX only, the API remains the authority via
    require_org_permission."""
    register_response = await register("alice@example.com")
    registered_org = register_response.json()["organizations"][0]
    token = await login("alice@example.com")

    response = await client.get("/v1/organizations", headers=auth_header(token))

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == registered_org["id"]
    assert items[0]["name"] == registered_org["name"]
    assert items[0]["role"] == "owner"


@pytest.mark.asyncio(loop_scope="session")
async def test_list_my_organizations_only_returns_own_memberships(
    client, register, login, auth_header, org_id_for
) -> None:
    """A caller never sees another user's unrelated organization in this
    list -- only orgs they actually belong to."""
    await register("owner@example.com")
    await register("stranger@example.com")
    token_stranger = await login("stranger@example.com")
    owner_org = await org_id_for("owner@example.com")

    response = await client.get(
        "/v1/organizations", headers=auth_header(token_stranger)
    )

    assert response.status_code == 200
    ids = [item["id"] for item in response.json()["items"]]
    assert owner_org not in ids


@pytest.mark.asyncio(loop_scope="session")
async def test_list_my_organizations_reflects_invited_role(
    client, register, login, auth_header, org_id_for
) -> None:
    await register("owner@example.com")
    await register("admin@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "admin@example.com", "role": "admin"},
        headers=auth_header(token_owner),
    )

    token_admin = await login("admin@example.com")
    response = await client.get("/v1/organizations", headers=auth_header(token_admin))

    assert response.status_code == 200
    items = response.json()["items"]
    entry = next(i for i in items if i["id"] == org)
    assert entry["role"] == "admin"


@pytest.mark.asyncio(loop_scope="session")
async def test_list_my_organizations_requires_auth(client) -> None:
    response = await client.get("/v1/organizations")

    assert response.status_code in (401, 403)
