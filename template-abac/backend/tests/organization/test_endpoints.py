import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import OrganizationMember
from tests.conftest import TwoTenants


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


@pytest.mark.asyncio(loop_scope="session")
async def test_adding_an_existing_member_is_idempotent(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    """Adding the same user twice returns 409 and never creates a second row."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    first = await client.post(
        f"/v1/organizations/{org_a}/members",
        json={"email": "bob@example.com"},
        headers=auth_header(token_alice),
    )
    assert first.status_code == 201

    second = await client.post(
        f"/v1/organizations/{org_a}/members",
        json={"email": "bob@example.com"},
        headers=auth_header(token_alice),
    )
    assert second.status_code == 409

    result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(org_a))
    )
    assert result.scalar_one() == 2  # alice (owner) + bob, no duplicate


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_add_member(
    client: AsyncClient,
    session: AsyncSession,
    auth_header,
    two_tenants: TwoTenants,
) -> None:
    """A non-member can't invite anyone into another org's membership
    list either -- same 404 gate, and it never reaches `add_member`."""
    response = await client.post(
        f"/v1/organizations/{two_tenants.org_a}/members",
        json={"email": "tenant-b@example.com"},
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404

    result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(two_tenants.org_a))
    )
    assert result.scalar_one() == 1  # only the org's own owner
