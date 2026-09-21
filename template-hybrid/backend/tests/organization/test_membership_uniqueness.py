"""Regression coverage for the duplicate-membership lockout bug.

Historically `OrganizationMember` had no unique constraint on
(organization_id, user_id) and `add_member` was an unconditional insert.
Two invites for the same user (sequential, or racing concurrently) could
both succeed, leaving two membership rows. `auth/dependencies.py::_get_membership`
uses `.scalar_one_or_none()`, so any request from that user against that
org afterwards raised `MultipleResultsFound` -> unhandled 500 -- a
permanent, self-inflicted lockout with no self-service recovery.
"""

import asyncio
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.repository import create_user
from kalekit.models.organization import MemberRole, OrganizationMember
from kalekit.organization.repository import (
    add_member,
    create_invitation,
    create_organization,
)
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)


@pytest_asyncio.fixture(loop_scope="session")
async def owner_and_org(engine: AsyncEngine) -> tuple[str, str]:
    """A fresh organization plus the id of a user not yet a member of it.

    Committed on its own session (rather than the function-scoped,
    never-committed `session` fixture used elsewhere) so the separate,
    concurrent sessions in the race test can actually see this data --
    two independent connections don't observe another session's
    uncommitted rows.
    """
    async with AsyncSession(engine, expire_on_commit=False) as setup_session:
        organization = await create_organization(setup_session, name="Race Co")
        invitee = await create_user(
            setup_session, "invitee-race@example.com", "password12345"
        )
        await setup_session.commit()
        return str(organization.id), str(invitee.id)


@pytest.mark.asyncio(loop_scope="session")
async def test_reaccepting_after_already_a_member_returns_409(
    client, register, login, auth_header, org_id_for, add_member, session: AsyncSession
) -> None:
    """A second, independently-issued invitation for someone who is
    already a member is rejected (409) when accepted, and never
    creates a duplicate row -- the acceptance criterion in the issue is
    explicit that this must not merely be caught by the race test.

    Also proves no privilege escalation slips through: the second
    invitation offers `admin`, so this also checks the existing row's
    role is still `member` afterwards -- the scenario the issue calls
    out as the privilege-escalation vector for this bug.
    """
    owner_register = await register("owner@example.com")
    await register("member@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")
    owner_id = uuid.UUID(owner_register.json()["id"])

    await add_member(org, token_member, "member@example.com", role=MemberRole.member)

    # A second, independently-issued invitation for the same email,
    # this time offering `admin` -- created directly (mirroring how the
    # invite endpoint itself would) rather than through the endpoint,
    # since only the token's hash is ever persisted for the endpoint to
    # give back.
    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org),
        email="member@example.com",
        role=MemberRole.admin,
        token_hash=hash_invitation_token(raw_token),
        invited_by=owner_id,
        expires_at=invitation_token_expiry(),
    )
    second_accept = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_member),
    )

    assert second_accept.status_code == 409

    rows = (
        (
            await session.execute(
                select(OrganizationMember).where(
                    OrganizationMember.organization_id == uuid.UUID(org),
                    OrganizationMember.role != MemberRole.owner,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].role == MemberRole.member


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_invites_race_exactly_one_wins(
    engine: AsyncEngine, owner_and_org: tuple[str, str]
) -> None:
    """Two truly concurrent invites of the same user, each on its own
    connection/session/transaction (a real race, not two calls sharing
    one AsyncSession which SQLAlchemy would refuse to interleave).

    Before the fix, this either raised an unhandled IntegrityError past
    `add_member` or -- absent the unique constraint entirely -- silently
    inserted two rows. After the fix, exactly one call reports
    `created=True` and the other `created=False`, and the DB ends up
    with exactly one row.
    """
    organization_id, user_id = owner_and_org

    async def _invite() -> tuple[OrganizationMember, bool]:
        async with AsyncSession(engine, expire_on_commit=False) as race_session:
            result = await add_member(
                race_session,
                organization_id=uuid.UUID(organization_id),
                user_id=uuid.UUID(user_id),
                role=MemberRole.member,
            )
            await race_session.commit()
            return result

    results = await asyncio.gather(_invite(), _invite())

    created_flags = sorted(created for _member, created in results)
    assert created_flags == [False, True]

    async with AsyncSession(engine) as verify_session:
        count = await verify_session.scalar(
            select(func.count())
            .select_from(OrganizationMember)
            .where(
                OrganizationMember.organization_id == uuid.UUID(organization_id),
                OrganizationMember.user_id == uuid.UUID(user_id),
            )
        )
        assert count == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_non_duplicated_member_still_works_normally(
    client, register, login, auth_header, org_id_for, add_member
) -> None:
    """Regression for `_get_membership`: a user with exactly one
    membership row must keep working (no spurious 500 from
    `scalar_one_or_none` seeing more than one row)."""
    await register("owner@example.com")
    await register("member@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")

    await add_member(org, token_member, "member@example.com", role=MemberRole.member)

    response = await client.get(
        f"/v1/organizations/{org}/members", headers=auth_header(token_member)
    )

    assert response.status_code == 200
    emails = {item["email"] for item in response.json()["items"]}
    assert emails == {"owner@example.com", "member@example.com"}
