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
from kalekit.organization.repository import add_member, create_organization


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
            setup_session, "invitee-race@example.com", "password123"
        )
        await setup_session.commit()
        return str(organization.id), str(invitee.id)


@pytest.mark.asyncio(loop_scope="session")
async def test_reinviting_existing_member_returns_409(
    client, register, login, auth_header, org_id_for, session: AsyncSession
) -> None:
    """Sequential duplicate invite: the second call must be rejected, not
    create a second row -- the acceptance criterion in the issue is
    explicit that this must not merely be caught by the race test.

    Also proves no privilege escalation slips through: the rejected
    second invite asks for `admin`, so this also checks the existing
    row's role is still `member` afterwards -- the scenario the issue
    calls out as the privilege-escalation vector for this bug.
    """
    await register("owner@example.com")
    await register("member@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    first = await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "member@example.com", "role": "member"},
        headers=auth_header(token_owner),
    )
    assert first.status_code == 201

    second = await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "member@example.com", "role": "admin"},
        headers=auth_header(token_owner),
    )

    assert second.status_code == 409

    rows = (
        (
            await session.execute(
                select(OrganizationMember).where(
                    OrganizationMember.organization_id == uuid.UUID(org),
                    OrganizationMember.user_id == uuid.UUID(first.json()["user_id"]),
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
    client, register, login, auth_header, org_id_for
) -> None:
    """Regression for `_get_membership`: a user with exactly one
    membership row must keep working (no spurious 500 from
    `scalar_one_or_none` seeing more than one row)."""
    await register("owner@example.com")
    await register("member@example.com")
    token_owner = await login("owner@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")

    invite = await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "member@example.com", "role": "member"},
        headers=auth_header(token_owner),
    )
    assert invite.status_code == 201

    response = await client.get(
        f"/v1/organizations/{org}/members", headers=auth_header(token_member)
    )

    assert response.status_code == 200
    emails = {item["email"] for item in response.json()["items"]}
    assert emails == {"owner@example.com", "member@example.com"}
