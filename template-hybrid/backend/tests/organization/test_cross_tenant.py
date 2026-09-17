import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import OrganizationMember
from tests.conftest import TwoTenants


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_list_members(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    """404, not 403 -- to a non-member, org A's members list doesn't
    exist rather than existing-but-forbidden."""
    response = await client.get(
        f"/v1/organizations/{two_tenants.org_a}/members",
        headers=auth_header(two_tenants.token_b),
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_invite(
    client: AsyncClient,
    session: AsyncSession,
    auth_header,
    two_tenants: TwoTenants,
) -> None:
    """A non-member can't invite anyone into another org's membership
    list either -- same 404 gate, and it never reaches `create_invitation`."""
    response = await client.post(
        f"/v1/organizations/{two_tenants.org_a}/invitations",
        json={"email": "tenant-b@example.com", "role": "member"},
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404

    result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(two_tenants.org_a))
    )
    assert result.scalar_one() == 1  # only org A's own owner
