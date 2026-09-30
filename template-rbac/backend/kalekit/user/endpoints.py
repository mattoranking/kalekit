import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import require_admin_permission
from kalekit.auth.repository import bump_token_version
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.user.repository import get_user_by_id, get_users, update_user
from kalekit.user.schemas import UserListResponse, UserResponse, UserUpdate
from kalekit.user.service import ensure_not_last_active_admin
from kalekit.user.sorting import DEFAULT_USER_SORT, UserSort

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/",
    response_model=UserListResponse,
    summary="Retrieve all users paginated",
)
async def list_users(
    session: Annotated[AsyncSession, Depends(get_db_session, scope="function")],
    # Back-office capability (listing every user): needs `users:read`
    # AND a token minted by the admin client (#6). Anyone else gets a
    # 404 so the route looks absent (#222).
    _caller: Annotated[User, Depends(require_admin_permission("users:read"))],
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20,
    q: Annotated[
        str | None,
        Query(max_length=255, description="Case-insensitive email substring"),
    ] = None,
    role: Annotated[
        str | None, Query(max_length=50, description="Role name held")
    ] = None,
    is_active: bool | None = None,
    sort: UserSort = DEFAULT_USER_SORT,
) -> UserListResponse:
    users, total = await get_users(
        session,
        page=page,
        size=size,
        q=q,
        role=role,
        is_active=is_active,
        sort=sort,
    )
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


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        email_verified=user.email_verified,
        created_at=user.created_at,
        roles=[ur.role.name for ur in user.roles],
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Retrieve one user",
)
async def get_user(
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _caller: Annotated[User, Depends(require_admin_permission("users:read"))],
) -> UserResponse:
    user = await get_user_by_id(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_response(user)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Suspend or reactivate a user",
)
async def patch_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[User, Depends(require_admin_permission("users:write"))],
) -> UserResponse:
    user = await get_user_by_id(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    suspending = user.is_active and not body.is_active
    if suspending:
        if user.id == caller.id:
            raise HTTPException(
                status_code=409,
                detail="You cannot deactivate yourself",
            )
        await ensure_not_last_active_admin(session, user)

    # TODO(#219): record_event(...)
    await update_user(session, user, is_active=body.is_active)
    if suspending:
        # get_current_user already refuses an inactive user; the version
        # bump also cuts off their access tokens for good, so
        # reactivating the account later does not revive a token issued
        # before the suspension (#195).
        await bump_token_version(session, user)
    return _user_response(user)
