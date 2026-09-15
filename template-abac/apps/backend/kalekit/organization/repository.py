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


async def add_member(
    session: AsyncSession, *, organization_id: uuid.UUID, user_id: uuid.UUID
) -> OrganizationMember:
    member = OrganizationMember(organization_id=organization_id, user_id=user_id)
    session.add(member)
    await session.flush()
    return member


async def list_members(
    session: AsyncSession, *, organization_id: uuid.UUID
) -> list[tuple[uuid.UUID, str]]:
    result = await session.execute(
        select(User.id, User.email)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .where(OrganizationMember.organization_id == organization_id)
    )
    return list(result.all())
