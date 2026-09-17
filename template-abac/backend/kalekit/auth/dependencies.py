from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.config import settings
from kalekit.models.organization import Organization, OrganizationMember
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.utils.db.tenancy import tenant_filter

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def require_org_member(
    organization_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    """Ownership gate: is this user a member of the org named in the path?

    Deliberately returns 404, not 403 — to a non-member, this
    organization's data doesn't exist rather than existing-but-forbidden.
    There is no permission lookup here at all: membership is the check.
    """
    result = await session.execute(
        select(OrganizationMember).where(
            tenant_filter(OrganizationMember, organization_id=organization_id),
            OrganizationMember.user_id == user.id,
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Not found")
    return user


async def require_org_creator(
    organization_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> Organization:
    """Invitation gate (issue #24): flat membership means everyone can
    read/write an org's data, but growing the tenant is not something
    membership alone should grant -- otherwise any member could pull
    arbitrary registered users into the org unilaterally. Only the
    org's creator may invite new members.

    404 (not 403) for a non-member, same reasoning as `require_org_member`
    -- the org doesn't exist for them. 403 for a member who isn't the
    creator -- they can see the org, they just can't grow it.
    """
    result = await session.execute(
        select(OrganizationMember).where(
            tenant_filter(OrganizationMember, organization_id=organization_id),
            OrganizationMember.user_id == user.id,
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Not found")

    organization = await session.get(Organization, organization_id)
    if organization is None or organization.created_by != user.id:
        raise HTTPException(
            status_code=403, detail="Only the organization creator can invite members"
        )
    return organization
