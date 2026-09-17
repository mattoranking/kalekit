import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import Organization, OrganizationMember
from tests.conftest import TwoTenants


@pytest.mark.asyncio(loop_scope="session")
async def test_creator_can_create_additional_organization(
    client: AsyncClient, register, login, auth_header
) -> None:
    await register("alice@example.com")
    token_alice = await login("alice@example.com")

    response = await client.post(
        "/v1/organizations",
        json={"name": "Alice's Second Org"},
        headers=auth_header(token_alice),
    )
    assert response.status_code == 201
    assert response.json()["name"] == "Alice's Second Org"

    orgs = await client.get("/v1/organizations", headers=auth_header(token_alice))
    assert len(orgs.json()["items"]) == 2


@pytest.mark.asyncio(loop_scope="session")
async def test_creator_can_rename_organization(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.patch(
        f"/v1/organizations/{org_a}",
        json={"name": "Renamed Org"},
        headers=auth_header(token_alice),
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Renamed Org"


@pytest.mark.asyncio(loop_scope="session")
async def test_non_creator_member_cannot_rename_organization(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    await add_member(org_a, token_bob, "bob@example.com")

    response = await client.patch(
        f"/v1/organizations/{org_a}",
        json={"name": "Bob's Hijack"},
        headers=auth_header(token_bob),
    )
    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_rename_organization(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    response = await client.patch(
        f"/v1/organizations/{two_tenants.org_a}",
        json={"name": "Hostile Rename"},
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_creator_can_remove_a_member(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
    add_member,
) -> None:
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    await add_member(org_a, token_bob, "bob@example.com")

    members_response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_alice)
    )
    bob_id = next(
        m["user_id"]
        for m in members_response.json()["items"]
        if m["email"] == "bob@example.com"
    )

    response = await client.delete(
        f"/v1/organizations/{org_a}/members/{bob_id}",
        headers=auth_header(token_alice),
    )
    assert response.status_code == 204

    count_result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(org_a))
    )
    assert count_result.scalar_one() == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_removing_the_last_member_is_refused(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    members_response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_alice)
    )
    alice_id = members_response.json()["items"][0]["user_id"]

    response = await client.delete(
        f"/v1/organizations/{org_a}/members/{alice_id}",
        headers=auth_header(token_alice),
    )
    assert response.status_code == 409


@pytest.mark.asyncio(loop_scope="session")
async def test_non_creator_member_cannot_remove_another_member(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("alice@example.com")
    await register("bob@example.com")
    await register("carol@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    await add_member(org_a, token_bob, "bob@example.com")
    await add_member(org_a, await login("carol@example.com"), "carol@example.com")

    members_response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_bob)
    )
    carol_id = next(
        m["user_id"]
        for m in members_response.json()["items"]
        if m["email"] == "carol@example.com"
    )

    response = await client.delete(
        f"/v1/organizations/{org_a}/members/{carol_id}",
        headers=auth_header(token_bob),
    )
    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_removing_unknown_member_returns_404(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.delete(
        f"/v1/organizations/{org_a}/members/{uuid.uuid4()}",
        headers=auth_header(token_alice),
    )
    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_remove_member(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    response = await client.delete(
        f"/v1/organizations/{two_tenants.org_a}/members/{uuid.uuid4()}",
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_member_can_leave_organization(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
    add_member,
) -> None:
    await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    await add_member(org_a, token_bob, "bob@example.com")

    response = await client.post(
        f"/v1/organizations/{org_a}/leave", headers=auth_header(token_bob)
    )
    assert response.status_code == 204

    count_result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(org_a))
    )
    assert count_result.scalar_one() == 1

    # Bob is no longer a member -- the org's endpoints now 404 for him.
    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_bob)
    )
    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_sole_member_cannot_leave_organization(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.post(
        f"/v1/organizations/{org_a}/leave", headers=auth_header(token_alice)
    )
    assert response.status_code == 409


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_leave_organization(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    response = await client.post(
        f"/v1/organizations/{two_tenants.org_a}/leave",
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_after_creator_leaves_any_member_can_rename(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
    add_member,
) -> None:
    """When the org's creator leaves, `created_by` is cleared so the org
    isn't permanently locked out of rename by a member who's no longer
    there -- any remaining member may rename it (see `require_org_admin`).
    """
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    await add_member(org_a, token_bob, "bob@example.com")

    leave_response = await client.post(
        f"/v1/organizations/{org_a}/leave", headers=auth_header(token_alice)
    )
    assert leave_response.status_code == 204

    organization = await session.get(Organization, uuid.UUID(org_a))
    assert organization is not None
    assert organization.created_by is None

    rename_response = await client.patch(
        f"/v1/organizations/{org_a}",
        json={"name": "Bob's Org Now"},
        headers=auth_header(token_bob),
    )
    assert rename_response.status_code == 200
    assert rename_response.json()["name"] == "Bob's Org Now"
