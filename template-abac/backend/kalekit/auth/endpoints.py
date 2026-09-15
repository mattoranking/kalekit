from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import get_current_user
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
from kalekit.auth.service import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from kalekit.models.user import User
from kalekit.organization.repository import add_member, create_organization
from kalekit.postgres import get_db_session

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    body: RegisterRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    existing = await find_user_by_email(session, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = await create_user(session, body.email, body.password)

    # Every user always belongs to at least one organization — there is
    # no such thing as a signup without a tenant in this style.
    org_name = body.organization_name or f"{body.email.split('@')[0]}'s workspace"
    organization = await create_organization(session, name=org_name)
    await add_member(session, organization_id=organization.id, user_id=user.id)

    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
        organizations=[organization.name],
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

    access_token = create_access_token(str(user.id))
    refresh_token, expires_at = create_refresh_token(str(user.id))

    await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_password(refresh_token),
        expires_at=expires_at,
        ip_address=request.client.host if request.client else None,
    )

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


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

    new_access = create_access_token(str(user.id))
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
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    await revoke_user_refresh_tokens(session, user.id)


@router.get("/me", response_model=UserResponse)
async def me(user: Annotated[User, Depends(get_current_user)]):
    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
        organizations=[m.organization.name for m in user.memberships],
    )
