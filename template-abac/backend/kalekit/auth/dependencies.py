from typing import Annotated, Any
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.config import settings
from kalekit.models.organization import Organization, OrganizationMember
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.utils.db.tenancy import tenant_filter

bearer_scheme = HTTPBearer()


def _signing_key_for_kid(kid: Any) -> str | None:
    """Resolve a token's `kid` header to the secret it was (or should
    have been) signed with -- the current key, or one of the previous
    keys kept around for rotation. None means "don't know this key",
    which the caller must treat as an invalid token.

    `kid` comes from the *unverified* token header, so it's arbitrary
    attacker-controlled JSON, not necessarily a string -- e.g. a list
    or dict, which would raise `TypeError: unhashable type` from the
    dict lookup below if not rejected first.
    """
    if not isinstance(kid, str) or not kid:
        return None
    if kid == settings.JWT_KID:
        return settings.JWT_SECRET_KEY
    return settings.JWT_PREVIOUS_KEYS.get(kid)


def _decode_access_token(credentials: HTTPAuthorizationCredentials) -> dict[str, Any]:
    token = credentials.credentials

    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    key = _signing_key_for_kid(kid)
    if key is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = jwt.decode(
            token,
            key,
            # Pinning the algorithm list (rather than trusting whatever
            # `alg` the token claims) is what closes the classic
            # "alg: none" / algorithm-confusion JWT attacks.
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            leeway=settings.JWT_LEEWAY_SECONDS,
            options={"require": ["exp", "aud", "iss"]},
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    payload = _decode_access_token(credentials)
    user_id = payload.get("sub")

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


async def require_org_admin(
    organization_id: UUID,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> Organization:
    """Rename / remove-member gate (issue #25): the org's creator, or
    any member if the org has no recorded creator -- e.g. the creator
    has since left or been removed (see `remove_member`), or a future
    system-seeded organization that was never given one.

    Same 404-for-non-member as `require_org_member` -- the org doesn't
    exist for them. 403 for a member who isn't the creator of an org
    that still has one.
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
    if organization is None:
        raise HTTPException(status_code=404, detail="Not found")
    if organization.created_by is not None and organization.created_by != user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the organization creator can perform this action",
        )
    return organization
