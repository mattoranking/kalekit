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
