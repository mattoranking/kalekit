import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


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


class RoleResponse(BaseModel):
    name: str
    description: str | None
    permissions: list[str]


class RoleListResponse(BaseModel):
    items: list[RoleResponse]


class UserRolesUpdate(BaseModel):
    """Body of PUT /v1/users/{id}/roles: the full set of role names the
    user should hold afterwards. An empty list removes every role."""

    model_config = ConfigDict(extra="forbid")

    roles: list[Annotated[str, StringConstraints(max_length=50)]] = Field(
        max_length=100
    )
