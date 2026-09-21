import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

from kalekit.auth.password_policy import NewPassword
from kalekit.organization.schemas import OrganizationMembershipResponse


class RegisterRequest(BaseModel):
    email: EmailStr
    password: NewPassword
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


class LogoutRequest(BaseModel):
    # Optional so a caller that only has the access token (it expired,
    # or was never persisted client-side) can still log out -- the
    # access token itself is always blocked. Passing the refresh token
    # additionally revokes just *this session's* family, rather than
    # leaving it able to mint fresh access tokens until it expires on
    # its own; see /auth/logout-all to end every session at once.
    refresh_token: str | None = None


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str | None
    is_active: bool
    created_at: datetime
    organizations: list[OrganizationMembershipResponse] = []

    model_config = {"from_attributes": True}
