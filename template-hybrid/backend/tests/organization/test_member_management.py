import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import MemberRole, OrganizationMember


async def _user_id_for(session: AsyncSession, org: str, email: str) -> uuid.UUID:
    from kalekit.models.user import User

    result = await session.execute(
        select(OrganizationMember.user_id)
        .join(User, User.id == OrganizationMember.user_id)
        .where(
            OrganizationMember.organization_id == uuid.UUID(org),
            User.email == email,
        )
    )
    return result.scalar_one()


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_change_a_members_role(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    await register("owner@example.com")
    await register("member@example.com")
    token_owner = await login("owner@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_member, "member@example.com", role=MemberRole.member)
    member_id = await _user_id_for(session, org, "member@example.com")

    response = await client.patch(
        f"/v1/organizations/{org}/members/{member_id}",
        json={"role": "admin"},
        headers=auth_header(token_owner),
    )

    assert response.status_code == 200
    assert response.json()["role"] == "admin"


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_cannot_promote_to_owner(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    """Same H-1 privilege-escalation rule applies to role changes, not
    just invitations."""
    await register("owner@example.com")
    await register("admin@example.com")
    await register("member@example.com")
    token_admin = await login("admin@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)
    await add_member(org, token_member, "member@example.com", role=MemberRole.member)
    member_id = await _user_id_for(session, org, "member@example.com")

    response = await client.patch(
        f"/v1/organizations/{org}/members/{member_id}",
        json={"role": "owner"},
        headers=auth_header(token_admin),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_cannot_demote_an_owner(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    """Only owners can act on owners -- an admin can't touch one even
    to demote them."""
    await register("owner@example.com")
    await register("second-owner@example.com")
    await register("admin@example.com")
    token_second_owner = await login("second-owner@example.com")
    token_admin = await login("admin@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(
        org, token_second_owner, "second-owner@example.com", role=MemberRole.owner
    )
    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)
    second_owner_id = await _user_id_for(session, org, "second-owner@example.com")

    response = await client.patch(
        f"/v1/organizations/{org}/members/{second_owner_id}",
        json={"role": "member"},
        headers=auth_header(token_admin),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_demote_another_owner_when_not_last(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    await register("owner@example.com")
    await register("second-owner@example.com")
    token_owner = await login("owner@example.com")
    token_second_owner = await login("second-owner@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(
        org, token_second_owner, "second-owner@example.com", role=MemberRole.owner
    )
    second_owner_id = await _user_id_for(session, org, "second-owner@example.com")

    response = await client.patch(
        f"/v1/organizations/{org}/members/{second_owner_id}",
        json={"role": "member"},
        headers=auth_header(token_owner),
    )

    assert response.status_code == 200
    assert response.json()["role"] == "member"


@pytest.mark.asyncio(loop_scope="session")
async def test_last_owner_cannot_be_demoted(
    client: AsyncClient, session: AsyncSession, register, login, auth_header, org_id_for
) -> None:
    owner_response = await register("owner@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")
    owner_id = uuid.UUID(owner_response.json()["id"])

    response = await client.patch(
        f"/v1/organizations/{org}/members/{owner_id}",
        json={"role": "admin"},
        headers=auth_header(token_owner),
    )

    assert response.status_code == 409
    result = await session.execute(
        select(OrganizationMember.role).where(
            OrganizationMember.organization_id == uuid.UUID(org),
            OrganizationMember.user_id == owner_id,
        )
    )
    assert result.scalar_one() == MemberRole.owner


@pytest.mark.asyncio(loop_scope="session")
async def test_last_owner_cannot_be_removed(
    client: AsyncClient, session: AsyncSession, register, login, auth_header, org_id_for
) -> None:
    owner_response = await register("owner@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")
    owner_id = uuid.UUID(owner_response.json()["id"])

    response = await client.delete(
        f"/v1/organizations/{org}/members/{owner_id}",
        headers=auth_header(token_owner),
    )

    assert response.status_code == 409
    result = await session.execute(
        select(OrganizationMember.role).where(
            OrganizationMember.organization_id == uuid.UUID(org),
            OrganizationMember.user_id == owner_id,
        )
    )
    assert result.scalar_one() == MemberRole.owner


@pytest.mark.asyncio(loop_scope="session")
async def test_last_owner_cannot_leave(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("owner@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    response = await client.post(
        f"/v1/organizations/{org}/leave",
        headers=auth_header(token_owner),
    )

    assert response.status_code == 409


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_remove_another_owner_when_not_last(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    await register("owner@example.com")
    await register("second-owner@example.com")
    token_owner = await login("owner@example.com")
    token_second_owner = await login("second-owner@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(
        org, token_second_owner, "second-owner@example.com", role=MemberRole.owner
    )
    second_owner_id = await _user_id_for(session, org, "second-owner@example.com")

    response = await client.delete(
        f"/v1/organizations/{org}/members/{second_owner_id}",
        headers=auth_header(token_owner),
    )

    assert response.status_code == 204


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_cannot_remove_an_owner(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    await register("owner@example.com")
    await register("second-owner@example.com")
    await register("admin@example.com")
    token_second_owner = await login("second-owner@example.com")
    token_admin = await login("admin@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(
        org, token_second_owner, "second-owner@example.com", role=MemberRole.owner
    )
    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)
    second_owner_id = await _user_id_for(session, org, "second-owner@example.com")

    response = await client.delete(
        f"/v1/organizations/{org}/members/{second_owner_id}",
        headers=auth_header(token_admin),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_remove_a_member(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    await register("owner@example.com")
    await register("admin@example.com")
    await register("member@example.com")
    token_admin = await login("admin@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)
    await add_member(org, token_member, "member@example.com", role=MemberRole.member)
    member_id = await _user_id_for(session, org, "member@example.com")

    response = await client.delete(
        f"/v1/organizations/{org}/members/{member_id}",
        headers=auth_header(token_admin),
    )

    assert response.status_code == 204

    result = await session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == uuid.UUID(org),
            OrganizationMember.user_id == member_id,
        )
    )
    assert result.scalar_one_or_none() is None


@pytest.mark.asyncio(loop_scope="session")
async def test_member_cannot_remove_another_member(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    """`members:manage` needs admin+ -- a plain member cannot remove
    anyone else, even at an equal or lower role."""
    await register("owner@example.com")
    await register("member@example.com")
    await register("viewer@example.com")
    token_member = await login("member@example.com")
    token_viewer = await login("viewer@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_member, "member@example.com", role=MemberRole.member)
    await add_member(org, token_viewer, "viewer@example.com", role=MemberRole.viewer)
    viewer_id = await _user_id_for(session, org, "viewer@example.com")

    response = await client.delete(
        f"/v1/organizations/{org}/members/{viewer_id}",
        headers=auth_header(token_member),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_member_can_leave(
    client: AsyncClient, session: AsyncSession, register, login, auth_header,
    org_id_for, add_member,
) -> None:
    """Leaving is open to any role, unlike removing someone else."""
    await register("owner@example.com")
    await register("member@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_member, "member@example.com", role=MemberRole.member)
    member_id = await _user_id_for(session, org, "member@example.com")

    response = await client.post(
        f"/v1/organizations/{org}/leave",
        headers=auth_header(token_member),
    )

    assert response.status_code == 204
    result = await session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == uuid.UUID(org),
            OrganizationMember.user_id == member_id,
        )
    )
    assert result.scalar_one_or_none() is None


@pytest.mark.asyncio(loop_scope="session")
async def test_removing_unknown_member_is_404(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("owner@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    response = await client.delete(
        f"/v1/organizations/{org}/members/{uuid.uuid4()}",
        headers=auth_header(token_owner),
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_change_role_cross_tenant(
    client: AsyncClient, auth_header, two_tenants
) -> None:
    response = await client.patch(
        f"/v1/organizations/{two_tenants.org_a}/members/{uuid.uuid4()}",
        json={"role": "member"},
        headers=auth_header(two_tenants.token_b),
    )

    assert response.status_code == 404
