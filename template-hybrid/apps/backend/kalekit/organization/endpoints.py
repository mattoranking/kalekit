from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import require_org_member, require_org_role
from kalekit.auth.repository import find_user_by_email
from kalekit.models.organization import MemberRole
from kalekit.models.user import User
from kalekit.organization.repository import add_member, list_members
from kalekit.organization.schemas import (
    AddMemberRequest,
    MemberListResponse,
    MemberResponse,
)
from kalekit.postgres import get_db_session

router = APIRouter(prefix="/organizations/{organization_id}", tags=["organizations"])


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
    _caller: Annotated[User, Depends(require_org_role(MemberRole.admin))],
) -> MemberResponse:
    """Only admin/owner can invite — and only up to the role they set."""
    user = await find_user_by_email(session, body.email)
    if user is None:
        raise HTTPException(status_code=404, detail="No user with that email")
    await add_member(
        session, organization_id=organization_id, user_id=user.id, role=body.role
    )
    return MemberResponse(user_id=user.id, email=user.email, role=body.role)
