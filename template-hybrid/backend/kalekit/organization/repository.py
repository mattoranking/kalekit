import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import MemberRole, Organization, OrganizationMember
from kalekit.models.user import User
from kalekit.utils.db.tenancy import tenant_filter


async def create_organization(session: AsyncSession, *, name: str) -> Organization:
    organization = Organization(name=name)
    session.add(organization)
    await session.flush()
    return organization


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
    existing = await session.execute(
        select(OrganizationMember).where(
            tenant_filter(OrganizationMember, organization_id=organization_id),
            OrganizationMember.user_id == user_id,
        )
    )
    member = existing.scalar_one_or_none()
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
        existing = await session.execute(
            select(OrganizationMember).where(
                tenant_filter(OrganizationMember, organization_id=organization_id),
                OrganizationMember.user_id == user_id,
            )
        )
        member = existing.scalar_one_or_none()
        if member is None:
            # Not the uniqueness violation we expected -- e.g. a stale
            # organization_id/user_id hitting a FK constraint. Re-raise
            # the original error instead of masking it with a confusing
            # NoResultFound from this re-fetch.
            raise
        return member, False
    return member, True


async def list_members(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> list[tuple[uuid.UUID, str, MemberRole]]:
    result = await session.execute(
        select(User.id, User.email, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .where(tenant_filter(OrganizationMember, organization_id=organization_id))
    )
    return list(result.all())
