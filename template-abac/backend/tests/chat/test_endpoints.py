import pytest
from httpx import AsyncClient


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
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """Same URL, same account -- only org membership changes the result."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/chat/", headers=auth_header(token_bob)
    )
    assert response.status_code == 404

    await client.post(
        f"/v1/organizations/{org_a}/members",
        json={"email": "bob@example.com"},
        headers=auth_header(token_alice),
    )

    response = await client.get(
        f"/v1/organizations/{org_a}/chat/", headers=auth_header(token_bob)
    )
    assert response.status_code == 200
