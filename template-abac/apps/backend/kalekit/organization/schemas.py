import uuid

from pydantic import BaseModel, EmailStr


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class MemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str


class MemberListResponse(BaseModel):
    items: list[MemberResponse]


class AddMemberRequest(BaseModel):
    email: EmailStr
