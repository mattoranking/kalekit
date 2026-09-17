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
    actually do (see `require_org_permission`).
    """

    id: uuid.UUID
    name: str
    role: MemberRole

    model_config = {"from_attributes": True}


class OrganizationListResponse(BaseModel):
    items: list[OrganizationMembershipResponse]


class MemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str | None
    role: MemberRole


class MemberListResponse(BaseModel):
    items: list[MemberResponse]


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: MemberRole = MemberRole.member


class InvitationAckResponse(BaseModel):
    """Always the same body whether or not `email` belongs to a
    registered user or is already a member -- see issue #24/#31. The
    only way to learn anything about the outcome is to actually hold
    the matching account and check GET /organizations for the new org."""

    detail: str = "If that email is eligible, an invitation has been sent."


class AcceptInvitationRequest(BaseModel):
    token: str


class ChangeMemberRoleRequest(BaseModel):
    role: MemberRole
