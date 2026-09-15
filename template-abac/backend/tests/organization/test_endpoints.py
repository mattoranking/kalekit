import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_list_and_add_members(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_alice)
    )
    assert response.status_code == 200
    assert len(response.json()["items"]) == 1

    response = await client.post(
        f"/v1/organizations/{org_a}/members",
        json={"email": "bob@example.com"},
        headers=auth_header(token_alice),
    )
    assert response.status_code == 201

    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_alice)
    )
    assert len(response.json()["items"]) == 2


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_see_members(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """404, not 403 -- to a non-member, this organization's members list
    doesn't exist rather than existing-but-forbidden."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_bob)
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_inviting_an_unknown_email_fails(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.post(
        f"/v1/organizations/{org_a}/members",
        json={"email": "nobody@example.com"},
        headers=auth_header(token_alice),
    )

    assert response.status_code == 404
