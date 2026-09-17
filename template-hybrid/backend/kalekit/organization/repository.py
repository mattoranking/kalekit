import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import MemberRole, Organization, OrganizationMember
from kalekit.models.organization_invitation import OrganizationInvitation
from kalekit.models.user import User
from kalekit.utils.db.tenancy import tenant_filter


class LastOwnerError(Exception):
    """Raised when a role change or removal would leave the organization
    with zero owners."""


async def create_organization(session: AsyncSession, *, name: str) -> Organization:
    organization = Organization(name=name)
    session.add(organization)
    await session.flush()
    return organization


async def get_member(
    session: AsyncSession, *, organization_id: uuid.UUID, user_id: uuid.UUID
) -> OrganizationMember | None:
    result = await session.execute(
        select(OrganizationMember).where(
            tenant_filter(OrganizationMember, organization_id=organization_id),
            OrganizationMember.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


async def add_member(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    role: MemberRole,
) -> tuple[OrganizationMember, bool]:
    """Insert a membership row, or return the existing one.

    Check-then-insert, with a DB-level `UniqueConstraint` as the real
    guard against two concurrent invites racing past the initial check
    -- the `IntegrityError` fallback is what makes the race safe, not
    the check itself. Returns `(member, created)`; a caller that must
    surface a 409 for an existing membership can key off `created`.
    """
    member = await get_member(
        session, organization_id=organization_id, user_id=user_id
    )
    if member is not None:
        return member, False

    member = OrganizationMember(
        organization_id=organization_id, user_id=user_id, role=role
    )
    session.add(member)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        member = await get_member(
            session, organization_id=organization_id, user_id=user_id
        )
        if member is None:
            # Not the uniqueness violation we expected -- e.g. a stale
            # organization_id/user_id hitting a FK constraint. Re-raise
            # the original error instead of masking it with a confusing
            # NoResultFound from this re-fetch.
            raise
        return member, False
    return member, True


async def _lock_organization(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> Organization | None:
    """Locks the organization row for the duration of the transaction.

    Serializes concurrent role-change/removal calls against the same
    org on this lock, so two requests racing to demote/remove the
    second-to-last owner can't both read "more than one owner left"
    before either commits -- the same race-safety pattern the ABAC
    template's `remove_member` uses for last-*member* protection,
    adapted here to count owners specifically.
    """
    result = await session.execute(
        select(Organization).where(Organization.id == organization_id).with_for_update()
    )
    return result.scalar_one_or_none()


async def _count_owners(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(
            tenant_filter(OrganizationMember, organization_id=organization_id),
            OrganizationMember.role == MemberRole.owner,
        )
    )
    return result.scalar_one()


async def change_member_role(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    role: MemberRole,
) -> OrganizationMember | None:
    """Changes `user_id`'s role within `organization_id`.

    Locks the organization row first (see `_lock_organization`) so a
    demotion away from `owner` can safely check "is this the last
    owner?" without racing a concurrent demotion/removal of another
    owner. Raises `LastOwnerError` if `user_id` is currently the sole
    owner and `role` is anything other than `owner` -- this covers
    both an admin demoting the last owner and the last owner demoting
    themselves.

    Returns the updated row, or `None` if `user_id` isn't a member of
    this organization.
    """
    organization = await _lock_organization(
        session, organization_id=organization_id
    )
    if organization is None:
        return None

    member = await get_member(
        session, organization_id=organization_id, user_id=user_id
    )
    if member is None:
        return None

    if member.role == MemberRole.owner and role != MemberRole.owner:
        owner_count = await _count_owners(session, organization_id=organization_id)
        if owner_count <= 1:
            raise LastOwnerError()

    member.role = role
    await session.flush()
    return member


async def remove_member(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
) -> OrganizationMember | None:
    """Removes `user_id` from `organization_id`.

    Locks the organization row first (see `_lock_organization`) so
    removal races the same way `change_member_role` does. Raises
    `LastOwnerError` if `user_id` is currently the organization's sole
    owner -- covers both an admin removing the last owner and the
    last owner removing/leaving themselves. (Removing the last
    *member* overall, when that member isn't the/an owner, is out of
    scope for issue #30 -- only last-owner protection was asked for.)

    Returns the removed row, or `None` if `user_id` wasn't a member of
    this organization.
    """
    organization = await _lock_organization(
        session, organization_id=organization_id
    )
    if organization is None:
        return None

    member = await get_member(
        session, organization_id=organization_id, user_id=user_id
    )
    if member is None:
        return None

    if member.role == MemberRole.owner:
        owner_count = await _count_owners(session, organization_id=organization_id)
        if owner_count <= 1:
            raise LastOwnerError()

    await session.delete(member)
    await session.flush()
    return member


async def list_members(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> list[tuple[uuid.UUID, str | None, MemberRole]]:
    result = await session.execute(
        select(User.id, User.email, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .where(tenant_filter(OrganizationMember, organization_id=organization_id))
    )
    return list(result.all())


async def create_invitation(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    email: str,
    role: MemberRole,
    token_hash: str,
    invited_by: uuid.UUID | None,
    expires_at: datetime,
) -> OrganizationInvitation:
    invitation = OrganizationInvitation(
        organization_id=organization_id,
        # Normalized here, not by callers -- `accept_invitation`'s
        # `user.email.lower() != invitation.email` comparison relies on
        # stored emails always being lowercase, and that invariant
        # should hold at the one place that writes the row rather than
        # depend on every caller remembering to lowercase first.
        email=email.lower(),
        role=role,
        token_hash=token_hash,
        invited_by=invited_by,
        expires_at=expires_at,
    )
    session.add(invitation)
    await session.flush()
    return invitation


async def get_valid_invitation_by_token_hash(
    session: AsyncSession, token_hash: str
) -> OrganizationInvitation | None:
    """A token is valid iff it exists, is unused, and hasn't expired."""
    result = await session.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.token_hash == token_hash
        )
    )
    invitation = result.scalar_one_or_none()
    if invitation is None:
        return None
    if invitation.accepted_at is not None:
        return None
    if invitation.expires_at < datetime.now(timezone.utc):
        return None
    return invitation


async def mark_invitation_accepted(
    session: AsyncSession, invitation: OrganizationInvitation
) -> None:
    invitation.accepted_at = datetime.now(timezone.utc)
    await session.flush()
