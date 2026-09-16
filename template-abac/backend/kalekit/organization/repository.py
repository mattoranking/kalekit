import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import Organization, OrganizationMember
from kalekit.models.user import User


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
            OrganizationMember.organization_id == organization_id,
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
    """
    existing = await get_member(
        session, organization_id=organization_id, user_id=user_id
    )
    if existing is not None:
        return existing, False

    member = OrganizationMember(organization_id=organization_id, user_id=user_id)
    session.add(member)
    await session.flush()
    return member, True


async def list_members(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> list[tuple[uuid.UUID, str]]:
    result = await session.execute(
        select(User.id, User.email)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .where(OrganizationMember.organization_id == organization_id)
    )
    return list(result.all())
