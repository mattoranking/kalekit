import uuid

from pydantic import BaseModel, EmailStr


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class OrganizationListResponse(BaseModel):
    items: list[OrganizationResponse]


class MemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str


class MemberListResponse(BaseModel):
    items: list[MemberResponse]


class InviteMemberRequest(BaseModel):
    email: EmailStr


class InvitationAckResponse(BaseModel):
    """Always the same body whether or not `email` belongs to a
    registered user or is already a member -- see issue #24. The only
    way to learn anything about the outcome is to actually hold the
    matching account and check GET /organizations for the new org."""

    detail: str = "If that email is eligible, an invitation has been sent."


class AcceptInvitationRequest(BaseModel):
    token: str
