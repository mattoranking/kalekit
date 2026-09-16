import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

from kalekit.organization.schemas import OrganizationResponse


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    organization_name: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    created_at: datetime
    organizations: list[OrganizationResponse] = []

    model_config = {"from_attributes": True}
