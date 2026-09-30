import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    email_verified: bool
    created_at: datetime
    roles: list[str] = []

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    """Body of PATCH /v1/users/{id}. Only `is_active` can change: an
    email change needs re-verification, so `email` (or any other field)
    is rejected with 422 rather than ignored."""

    model_config = ConfigDict(extra="forbid")

    is_active: bool


class UserListResponse(BaseModel):
    items: list[UserResponse]
    total: int
    page: int
    size: int
