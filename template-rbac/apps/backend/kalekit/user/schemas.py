import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    created_at: datetime
    roles: list[str] = []

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    is_active: bool | None = None


class UserListResponse(BaseModel):
    items: list[UserResponse]
    total: int
    page: int
    size: int
