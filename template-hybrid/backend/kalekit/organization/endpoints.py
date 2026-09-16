from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import (
    OrgActor,
    get_current_user,
    require_org_member,
    require_org_permission,
)
from kalekit.auth.repository import find_user_by_email
from kalekit.auth.roles import role_at_least
from kalekit.models.organization import MemberRole
from kalekit.models.user import User
from kalekit.organization.repository import add_member, list_members
from kalekit.organization.schemas import (
    AddMemberRequest,
    MemberListResponse,
    MemberResponse,
    OrganizationListResponse,
    OrganizationMembershipResponse,
)
from kalekit.postgres import get_db_session

# Not scoped to a single organization_id -- this lists the caller's own
# memberships, so it lives at /organizations rather than
# /organizations/{organization_id}.
list_router = APIRouter(prefix="/organizations", tags=["organizations"])

router = APIRouter(prefix="/organizations/{organization_id}", tags=["organizations"])


@list_router.get("", response_model=OrganizationListResponse)
async def list_my_organizations(
    user: Annotated[User, Depends(get_current_user)],
) -> OrganizationListResponse:
    """The organizations the caller belongs to, plus their role in each.

    UX only -- for deciding what to show (e.g. "delete", "invite",
    settings controls), not authorization. The API remains the
    authority via `require_org_role` / `require_org_permission`.
    """
    return OrganizationListResponse(
        items=[
            OrganizationMembershipResponse(
                id=m.organization.id, name=m.organization.name, role=m.role
            )
            for m in user.memberships
        ]
    )


@router.get("/members", response_model=MemberListResponse)
async def get_members(
    organization_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _caller: Annotated[User, Depends(require_org_member)],
) -> MemberListResponse:
    """Any role can see the roster — this is a read, not a change."""
    rows = await list_members(session, organization_id=organization_id)
    return MemberListResponse(
        items=[
            MemberResponse(user_id=uid, email=email, role=role)
            for uid, email, role in rows
        ]
    )


@router.post("/members", response_model=MemberResponse, status_code=201)
async def add_organization_member(
    organization_id: UUID,
    body: AddMemberRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[OrgActor, Depends(require_org_permission("members:invite"))],
) -> MemberResponse:
    """Only admin/owner can invite — and only up to the role they hold.

    Granting `owner` additionally requires the caller themselves be
    `owner` — an admin can invite admin/member/viewer, never owner.
    """
    if not role_at_least(caller.role, body.role):
        raise HTTPException(
            status_code=403,
            detail="Cannot grant a role higher than your own",
        )
    if body.role == MemberRole.owner and caller.role != MemberRole.owner:
        raise HTTPException(
            status_code=403,
            detail="Only an owner can grant the owner role",
        )
    user = await find_user_by_email(session, body.email)
    if user is None:
        raise HTTPException(status_code=404, detail="No user with that email")
    member, created = await add_member(
        session, organization_id=organization_id, user_id=user.id, role=body.role
    )
    if not created:
        raise HTTPException(
            status_code=409, detail="User is already a member of this organization"
        )
    return MemberResponse(user_id=user.id, email=user.email, role=member.role)
