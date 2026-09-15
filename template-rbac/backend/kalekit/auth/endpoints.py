from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import get_current_jti, get_current_user
from kalekit.auth.permissions import block_token, get_scopes_for_roles
from kalekit.auth.repository import (
    create_user,
    find_user_by_email,
    revoke_user_refresh_tokens,
    store_refresh_token,
)
from kalekit.auth.schemas import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from kalekit.auth.seed import assign_role, ensure_default_roles
from kalekit.auth.service import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from kalekit.models.user import User
from kalekit.postgres import get_db_session

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    body: RegisterRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    existing = await find_user_by_email(session, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = await create_user(session, body.email, body.password)

    visitor_role, admin_role = await ensure_default_roles(session)
    user_count = (await session.execute(select(func.count(User.id)))).scalar_one()
    assigned_role = admin_role if user_count == 1 else visitor_role
    await assign_role(session, user, assigned_role)

    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
        roles=[assigned_role.name],
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    user = await find_user_by_email(session, body.email)
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")

    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    access_token = create_access_token(str(user.id), list(scopes))
    refresh_token, expires_at = create_refresh_token(str(user.id))

    await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_password(refresh_token),
        expires_at=expires_at,
        ip_address=request.client.host if request.client else None,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    from jose import JWTError
    from jose import jwt as jose_jwt

    from kalekit.config import settings

    try:
        payload = jose_jwt.decode(
            body.refresh_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")

    # Rotate: revoke all old tokens, issue new pair
    await revoke_user_refresh_tokens(session, user.id)

    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    new_access = create_access_token(str(user.id), list(scopes))
    new_refresh, expires_at = create_refresh_token(str(user.id))

    await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_password(new_refresh),
        expires_at=expires_at,
        ip_address=request.client.host if request.client else None,
    )

    return TokenResponse(access_token=new_access, refresh_token=new_refresh)


@router.post("/logout", status_code=204)
async def logout(
    user: Annotated[User, Depends(get_current_user)],
    jti: Annotated[str | None, Depends(get_current_jti)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    await revoke_user_refresh_tokens(session, user.id)
    # Without this, the access token used to call /logout stays valid
    # for the rest of its natural lifetime -- logging out wouldn't
    # actually revoke the thing that grants access.
    if jti:
        await block_token(jti)


@router.get("/me", response_model=UserResponse)
async def me(user: Annotated[User, Depends(get_current_user)]):
    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
        roles=[ur.role.name for ur in user.roles],
    )
