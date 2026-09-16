from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.blocklist import is_token_blocked, is_user_blocked
from kalekit.auth.roles import role_has_permission
from kalekit.config import settings
from kalekit.models.organization import MemberRole, OrganizationMember
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
        jti = payload.get("jti")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if jti and await is_token_blocked(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    if user_id and await is_user_blocked(user_id):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    user = await session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_current_jti(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> str | None:
    """The current access token's unique id, for revoking it by itself
    (e.g. on logout) rather than every token the user holds."""
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload.get("jti")


async def _get_membership(
    session: AsyncSession, organization_id: UUID, user_id: UUID
) -> OrganizationMember | None:
    result = await session.execute(
        select(OrganizationMember).where(
            tenant_filter(OrganizationMember, organization_id=organization_id),
            OrganizationMember.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


async def require_org_member(
    organization_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    """Ownership gate only — any role in the org passes.

    Deliberately returns 404, not 403 — to a non-member, this
    organization's data doesn't exist rather than existing-but-forbidden.
    """
    membership = await _get_membership(session, organization_id, user.id)
    if membership is None:
        raise HTTPException(status_code=404, detail="Not found")
    return user


@dataclass(frozen=True)
class OrgActor:
    """The caller plus the role they hold in the org being acted on.

    Returned by `require_org_permission` so endpoints can make further,
    role-sensitive decisions (e.g. "can I grant the role I was asked to
    grant?") without a second membership query.
    """

    user: User
    role: MemberRole


def require_org_permission(permission: str):
    """Dependency factory: ownership gate, then a permission within it.

    Checks "can this role do X?" against the `ROLE_PERMISSIONS` mapping in
    `auth/roles.py`, so endpoints declare what they need instead of
    encoding a rank ordering that breaks for non-linear roles.

    This never grants access on its own — it only narrows a caller who
    already passed the membership check.
    """

    async def checker(
        organization_id: UUID,
        user: Annotated[User, Depends(get_current_user)],
        session: Annotated[AsyncSession, Depends(get_db_session)],
    ) -> OrgActor:
        membership = await _get_membership(session, organization_id, user.id)
        if membership is None:
            raise HTTPException(status_code=404, detail="Not found")
        if not role_has_permission(membership.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Requires the '{permission}' permission",
            )
        return OrgActor(user=user, role=membership.role)

    return checker
