"""Regression coverage for a privilege-escalation race in role
change/removal.

Both `change_member_role` and `remove_member` gate the caller against
the target's *current* role (only an owner may act on an owner -- see
`auth/roles.py::ROLE_PERMISSIONS`'s `members:grant:<role>` entries).
That authorization check must be made against a role read taken
*after* the organization row is locked (`_lock_organization`), not
against an earlier, unlocked fetch -- otherwise two concurrent
requests can interleave so that a caller who was only ever authorized
against a target's *old* role (e.g. `member`) ends up acting on that
same target after a different, concurrent request has already
promoted them to `owner`.

A purely timing-based test (two real HTTP requests raced with
`asyncio.gather`) can't reliably reproduce this: which coroutine's
`SELECT ... FOR UPDATE` gets scheduled first, and whether a stale
pre-fetch actually lands before the competing commit, depends on
scheduler/IO timing that isn't controllable from a test and would
make the regression flaky in exactly the way that matters least (it
would sometimes "pass" even against the vulnerable code). Instead,
`_lock_organization` is monkeypatched so that -- once
`remove_member`/`change_member_role` has acquired the organization
lock -- a *separate, independently committed* session promotes the
target to `owner` before the patched function returns control. This
deterministically forces the exact interleaving the bug depended on:
a concurrent role change that lands after the lock is taken but
before the target's role is (re-)read for authorization. If that
fresh read happened outside the lock (the pre-fix ordering), it would
still see the stale `member` role and permit the action; reading it
*after* `_lock_organization` -- which is what the fix does -- means
it always sees the promotion and correctly refuses.
"""

import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import kalekit.organization.repository as org_repository
from kalekit.auth.repository import create_user
from kalekit.models.organization import MemberRole, OrganizationMember
from kalekit.organization.repository import (
    NotPermittedError,
    add_member,
    create_organization,
    get_member,
)


@pytest_asyncio.fixture(loop_scope="session")
async def committed_org_with_member_target(
    engine: AsyncEngine,
) -> AsyncGenerator[tuple[uuid.UUID, uuid.UUID]]:
    """A committed organization with an owner and a second member
    (`target`, role `member`) -- committed for real on their own
    session, since the race below needs a second, independent
    connection to see this data (the function-scoped `session` fixture
    used elsewhere only ever rolls back).

    Yields `(organization_id, target_user_id)`.
    """
    # Committed for real (not rolled back), so each invocation of this
    # fixture needs unique emails -- it can run more than once within
    # the same test session.
    suffix = uuid.uuid4().hex[:8]
    async with AsyncSession(engine, expire_on_commit=False) as setup_session:
        owner = await create_user(
            setup_session, f"race-owner3-{suffix}@example.com", "password12345"
        )
        organization = await create_organization(setup_session, name="Race Co 3")
        await add_member(
            setup_session,
            organization_id=organization.id,
            user_id=owner.id,
            role=MemberRole.owner,
        )
        target = await create_user(
            setup_session, f"race-target3-{suffix}@example.com", "password12345"
        )
        await add_member(
            setup_session,
            organization_id=organization.id,
            user_id=target.id,
            role=MemberRole.member,
        )
        await setup_session.commit()
        yield organization.id, target.id


async def _promote_target_to_owner_on_own_connection(
    engine: AsyncEngine, *, organization_id: uuid.UUID, target_id: uuid.UUID
) -> None:
    """Simulates a fully independent, concurrent request that promotes
    `target_id` to `owner` and commits -- on its own connection, so the
    commit is really visible to other sessions rather than just
    flushed within one shared transaction."""
    async with AsyncSession(engine, expire_on_commit=False) as other_session:
        other_member = await get_member(
            other_session, organization_id=organization_id, user_id=target_id
        )
        assert other_member is not None
        other_member.role = MemberRole.owner
        await other_session.commit()


@pytest.mark.asyncio(loop_scope="session")
async def test_remove_member_reads_role_after_lock_not_before(
    engine: AsyncEngine,
    committed_org_with_member_target: tuple[uuid.UUID, uuid.UUID],
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forces a concurrent promotion to land in the window right after
    `remove_member` acquires the organization lock. An admin's removal
    of `target` -- who was `member` when the request was issued but is
    `owner` by the time the authorization decision is actually made --
    must be refused (`NotPermittedError`), not silently allowed through
    on stale data.
    """
    organization_id, target_id = committed_org_with_member_target

    original_lock = org_repository._lock_organization

    async def _lock_then_race(session, *, organization_id):
        organization = await original_lock(session, organization_id=organization_id)
        # Runs *after* the lock is held but *before* `remove_member` goes
        # on to (re-)read the target's role -- exactly the window the
        # fix's ordering (lock, then read, then authorize) is meant to
        # close.
        await _promote_target_to_owner_on_own_connection(
            engine, organization_id=organization_id, target_id=target_id
        )
        return organization

    monkeypatch.setattr(org_repository, "_lock_organization", _lock_then_race)

    with pytest.raises(NotPermittedError):
        await org_repository.remove_member(
            session,
            organization_id=organization_id,
            user_id=target_id,
            caller_role=MemberRole.admin,
        )

    # Not removed -- the (correctly refused) attempt must not have
    # deleted the now-owner row.
    async with AsyncSession(engine, expire_on_commit=False) as verify_session:
        result = await verify_session.execute(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == target_id,
            )
        )
        remaining = result.scalar_one_or_none()
        assert remaining is not None
        assert remaining.role == MemberRole.owner


@pytest.mark.asyncio(loop_scope="session")
async def test_change_member_role_reads_role_after_lock_not_before(
    engine: AsyncEngine,
    committed_org_with_member_target: tuple[uuid.UUID, uuid.UUID],
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same race as above, exercised against `change_member_role`
    instead of `remove_member`: an admin's attempt to demote `target`
    (who is promoted to `owner` mid-flight, after the lock is taken)
    must be refused rather than silently demoting a now-owner."""
    organization_id, target_id = committed_org_with_member_target

    original_lock = org_repository._lock_organization

    async def _lock_then_race(session, *, organization_id):
        organization = await original_lock(session, organization_id=organization_id)
        await _promote_target_to_owner_on_own_connection(
            engine, organization_id=organization_id, target_id=target_id
        )
        return organization

    monkeypatch.setattr(org_repository, "_lock_organization", _lock_then_race)

    with pytest.raises(NotPermittedError):
        await org_repository.change_member_role(
            session,
            organization_id=organization_id,
            user_id=target_id,
            role=MemberRole.viewer,
            caller_role=MemberRole.admin,
        )

    async with AsyncSession(engine, expire_on_commit=False) as verify_session:
        result = await verify_session.execute(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == target_id,
            )
        )
        remaining = result.scalar_one_or_none()
        assert remaining is not None
        # Still owner -- the refused demotion must not have applied.
        assert remaining.role == MemberRole.owner
