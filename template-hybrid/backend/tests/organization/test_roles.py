import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import MemberRole, OrganizationMember
from kalekit.organization.repository import create_invitation
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_invite_at_any_role(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("owner@example.com")
    await register("viewer@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    response = await client.post(
        f"/v1/organizations/{org}/invitations",
        json={"email": "viewer@example.com", "role": "viewer"},
        headers=auth_header(token_owner),
    )

    assert response.status_code == 202


@pytest.mark.asyncio(loop_scope="session")
async def test_viewer_cannot_invite(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    """Inviting needs admin+ -- a viewer, even though they're a real
    member of the org, is refused."""
    await register("owner@example.com")
    await register("viewer@example.com")
    await register("intruder@example.com")
    token_viewer = await login("viewer@example.com")
    org = await org_id_for("owner@example.com")

    await add_member(org, token_viewer, "viewer@example.com", role=MemberRole.viewer)

    response = await client.post(
        f"/v1/organizations/{org}/invitations",
        json={"email": "intruder@example.com", "role": "member"},
        headers=auth_header(token_viewer),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_invite(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("owner@example.com")
    await register("admin@example.com")
    await register("newperson@example.com")
    token_admin = await login("admin@example.com")
    org = await org_id_for("owner@example.com")

    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)

    response = await client.post(
        f"/v1/organizations/{org}/invitations",
        json={"email": "newperson@example.com", "role": "member"},
        headers=auth_header(token_admin),
    )

    assert response.status_code == 202


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_cannot_invite_as_owner(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    """H-1: an admin must not be able to escalate an invitee straight to
    owner -- this is the privilege-escalation regression test."""
    await register("owner@example.com")
    await register("admin@example.com")
    await register("intruder@example.com")
    token_admin = await login("admin@example.com")
    org = await org_id_for("owner@example.com")

    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)

    response = await client.post(
        f"/v1/organizations/{org}/invitations",
        json={"email": "intruder@example.com", "role": "owner"},
        headers=auth_header(token_admin),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_invite_at_or_below_own_role(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    """An admin can still invite admin, member, and viewer -- only
    granting a role above their own (owner) is blocked."""
    await register("owner@example.com")
    await register("admin@example.com")
    token_admin = await login("admin@example.com")
    org = await org_id_for("owner@example.com")

    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)

    for role in ("admin", "member", "viewer"):
        response = await client.post(
            f"/v1/organizations/{org}/invitations",
            json={"email": f"new-{role}@example.com", "role": role},
            headers=auth_header(token_admin),
        )
        assert response.status_code == 202


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_invite_another_owner(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """Only an owner can grant the owner role -- confirm that owners
    themselves are still allowed to."""
    await register("owner@example.com")
    await register("second-owner@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    response = await client.post(
        f"/v1/organizations/{org}/invitations",
        json={"email": "second-owner@example.com", "role": "owner"},
        headers=auth_header(token_owner),
    )

    assert response.status_code == 202


@pytest.mark.asyncio(loop_scope="session")
async def test_accepting_grants_the_role_offered_in_the_invitation(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    """The membership created on accept carries the role the invitation
    named, surfaced back in the response."""
    owner_response = await register("owner@example.com")
    await register("newadmin@example.com")
    token_newadmin = await login("newadmin@example.com")
    org = await org_id_for("owner@example.com")
    owner_id = uuid.UUID(owner_response.json()["id"])

    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org),
        email="newadmin@example.com",
        role=MemberRole.admin,
        token_hash=hash_invitation_token(raw_token),
        invited_by=owner_id,
        expires_at=invitation_token_expiry(),
    )

    response = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_newadmin),
    )

    assert response.status_code == 201
    assert response.json()["role"] == "admin"


@pytest.mark.asyncio(loop_scope="session")
async def test_demoted_inviters_pending_invitation_cannot_be_accepted(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
    add_member,
) -> None:
    """H-3 / #31: an invitation created by an admin who has since been
    demoted cannot grant a role the admin no longer could -- even
    though the invitation itself was created while they still had the
    permission to offer it. The role is re-checked against the
    inviter's *current* role at accept time, not just at invite time.
    """
    await register("owner@example.com")
    await register("admin@example.com")
    await register("invitee@example.com")
    token_admin = await login("admin@example.com")
    token_invitee = await login("invitee@example.com")
    org = await org_id_for("owner@example.com")

    await add_member(org, token_admin, "admin@example.com", role=MemberRole.admin)

    result = await session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == uuid.UUID(org),
            OrganizationMember.role == MemberRole.admin,
        )
    )
    admin_membership = result.scalar_one()
    admin_id = admin_membership.user_id

    # The admin invites someone at `admin` -- allowed while they still
    # hold that role. Created directly (the invite endpoint never
    # returns the raw token, only emails it).
    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org),
        email="invitee@example.com",
        role=MemberRole.admin,
        token_hash=hash_invitation_token(raw_token),
        invited_by=admin_id,
        expires_at=invitation_token_expiry(),
    )

    # The admin is then demoted to member -- directly, since there's no
    # "change role" endpoint yet.
    admin_membership.role = MemberRole.member
    await session.flush()

    response = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_invitee),
    )

    assert response.status_code == 403

    # No membership was created for the invitee -- the invitation was
    # refused outright, not silently downgraded to whatever the
    # now-demoted admin can still grant.
    invitee_membership = await session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == uuid.UUID(org),
        )
    )
    roles_present = {m.role for m in invitee_membership.scalars().all()}
    assert MemberRole.owner in roles_present
    assert MemberRole.member in roles_present  # the demoted former admin
    assert MemberRole.admin not in roles_present


@pytest.mark.asyncio(loop_scope="session")
async def test_a_still_sufficiently_privileged_inviters_invitation_still_works(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    """The accept-time re-check doesn't punish an inviter who still
    holds a role capable of granting what they offered -- only a
    genuine downgrade below that threshold is refused."""
    owner_response = await register("owner@example.com")
    await register("invitee@example.com")
    token_invitee = await login("invitee@example.com")
    org = await org_id_for("owner@example.com")
    owner_id = uuid.UUID(owner_response.json()["id"])

    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org),
        email="invitee@example.com",
        role=MemberRole.member,
        token_hash=hash_invitation_token(raw_token),
        invited_by=owner_id,
        expires_at=invitation_token_expiry(),
    )

    response = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_invitee),
    )

    assert response.status_code == 201
    assert response.json()["role"] == "member"
