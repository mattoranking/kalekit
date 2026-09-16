from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import require_permission
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.user.repository import get_users
from kalekit.user.schemas import UserListResponse, UserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/",
    response_model=UserListResponse,
    summary="Retrieve all users paginated",
)
async def list_users(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _caller: Annotated[User, Depends(require_permission("users:read"))],
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> UserListResponse:
    users, total = await get_users(session, page=page, size=size)
    return UserListResponse(
        items=[
            UserResponse(
                id=u.id,
                email=u.email,
                is_active=u.is_active,
                email_verified=u.email_verified,
                created_at=u.created_at,
                roles=[ur.role.name for ur in u.roles],
            )
            for u in users
        ],
        total=total,
        page=page,
        size=size,
    )
