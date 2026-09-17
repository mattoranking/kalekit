import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import Organization, OrganizationMember
from kalekit.models.organization_invitation import OrganizationInvitation
from kalekit.models.user import User
from kalekit.utils.db.tenancy import tenant_filter


async def create_organization(
    session: AsyncSession, *, name: str, created_by: uuid.UUID | None = None
) -> Organization:
    organization = Organization(name=name, created_by=created_by)
    session.add(organization)
    await session.flush()
    return organization


async def get_organization(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> Organization | None:
    return await session.get(Organization, organization_id)


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
    session: AsyncSession, *, organization_id: uuid.UUID, user_id: uuid.UUID
) -> tuple[OrganizationMember, bool]:
    """Adds a user to an organization, idempotently.

    Returns the membership row and whether it was newly created. If the
    user is already a member, the existing row is returned instead of
    inserting a duplicate (organization_id, user_id) pair.

    Check-then-insert, with the DB-level `UniqueConstraint` on
    (organization_id, user_id) as the real guard against two concurrent
    invites racing past the initial check -- the `IntegrityError`
    fallback below is what makes the race safe, not the check itself.
    """
    existing = await get_member(
        session, organization_id=organization_id, user_id=user_id
    )
    if existing is not None:
        return existing, False

    member = OrganizationMember(organization_id=organization_id, user_id=user_id)
    session.add(member)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        existing = await get_member(
            session, organization_id=organization_id, user_id=user_id
        )
        if existing is None:
            # Not the uniqueness violation we expected -- e.g. a stale
            # organization_id/user_id hitting a FK constraint. Re-raise
            # the original error rather than masking it.
            raise
        return existing, False
    return member, True


async def list_user_organizations(
    session: AsyncSession, *, user_id: uuid.UUID
) -> list[Organization]:
    result = await session.execute(
        select(Organization)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user_id)
    )
    return list(result.scalars().all())


async def list_members(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> list[tuple[uuid.UUID, str | None]]:
    result = await session.execute(
        select(User.id, User.email)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .where(tenant_filter(OrganizationMember, organization_id=organization_id))
    )
    return list(result.all())


async def create_invitation(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    email: str,
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
