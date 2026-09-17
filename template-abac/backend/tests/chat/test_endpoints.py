import pytest
from httpx import AsyncClient

from tests.conftest import TwoTenants


@pytest.mark.asyncio(loop_scope="session")
async def test_member_can_post_and_read(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("alice@example.com")
    token = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.post(
        f"/v1/organizations/{org_a}/chat/",
        json={"content": "hi"},
        headers=auth_header(token),
    )
    assert response.status_code == 201

    response = await client.get(
        f"/v1/organizations/{org_a}/chat/", headers=auth_header(token)
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_gets_404_not_403(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """The ownership gate: a non-member's request never even reaches the
    query -- the org's chat doesn't exist for them, no permission error."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/chat/", headers=auth_header(token_bob)
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_membership_resolves_the_absence(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    """Same URL, same account -- only org membership changes the result."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/chat/", headers=auth_header(token_bob)
    )
    assert response.status_code == 404

    await add_member(org_a, token_bob, "bob@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/chat/", headers=auth_header(token_bob)
    )
    assert response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_post_message(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    """POST is org-scoped too -- a non-member can't write into another
    org's chat, and no message is created as a side effect of trying."""
    response = await client.post(
        f"/v1/organizations/{two_tenants.org_a}/chat/",
        json={"content": "should not land"},
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404

    response = await client.get(
        f"/v1/organizations/{two_tenants.org_a}/chat/",
        headers=auth_header(two_tenants.token_a),
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0
