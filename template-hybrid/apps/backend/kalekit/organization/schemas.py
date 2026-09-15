import uuid

from pydantic import BaseModel, EmailStr

from kalekit.models.organization import MemberRole


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class MemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    role: MemberRole


class MemberListResponse(BaseModel):
    items: list[MemberResponse]


class AddMemberRequest(BaseModel):
    email: EmailStr
    role: MemberRole = MemberRole.member
