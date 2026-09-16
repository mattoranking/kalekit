import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


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


class VerifyEmailRequest(BaseModel):
    token: str


class MessageResponse(BaseModel):
    detail: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    email_verified: bool
    created_at: datetime
    roles: list[str] = []

    model_config = {"from_attributes": True}
