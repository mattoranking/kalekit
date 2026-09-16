import uuid

from pydantic import BaseModel, EmailStr

from kalekit.models.organization import MemberRole


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class OrganizationMembershipResponse(BaseModel):
    """An organization plus the caller's role in it.

    UX only -- clients use this to show/hide controls (e.g. "delete",
    "invite"), but the API remains the authority on what a role can
    actually do (see `require_org_role` / `require_org_permission`).
    """

    id: uuid.UUID
    name: str
    role: MemberRole

    model_config = {"from_attributes": True}


class OrganizationListResponse(BaseModel):
    items: list[OrganizationMembershipResponse]


class MemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    role: MemberRole


class MemberListResponse(BaseModel):
    items: list[MemberResponse]


class AddMemberRequest(BaseModel):
    email: EmailStr
    role: MemberRole = MemberRole.member
