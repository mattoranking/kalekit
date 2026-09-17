from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.blocklist import (
    block_all_user_tokens,
    block_token,
    cache_refresh_grace_pair,
    get_cached_refresh_grace_pair,
)
from kalekit.auth.dependencies import get_current_jti, get_current_user
from kalekit.auth.repository import (
    create_user,
    find_user_by_email,
    get_refresh_token_by_hash,
    get_refresh_token_by_id,
    mark_refresh_token_replaced,
    revoke_refresh_token_family,
    revoke_user_refresh_tokens,
    store_refresh_token,
)
from kalekit.auth.schemas import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from kalekit.auth.service import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
    verify_password,
)
from kalekit.config import settings
from kalekit.models.organization import MemberRole
from kalekit.models.user import User
from kalekit.organization.repository import add_member, create_organization
from kalekit.organization.schemas import OrganizationMembershipResponse
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
    # no such thing as a signup without a tenant in this style. The
    # person who creates an organization is always its owner. The
    # default name must never be derived from the email address: that
    # local part becomes visible to anyone later invited to the org.
    org_name = body.organization_name or "My workspace"
    organization = await create_organization(session, name=org_name)
    # add_member returns (member, created); discarded here on purpose --
    # this is a brand-new organization, so the membership is always
    # freshly created (created=True). Don't assume that still holds if
    # this call site ever changes to reuse an existing organization.
    await add_member(
        session,
        organization_id=organization.id,
        user_id=user.id,
        role=MemberRole.owner,
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
        organizations=[
            OrganizationMembershipResponse(
                id=organization.id, name=organization.name, role=MemberRole.owner
            )
        ],
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
    refresh_token, expires_at = generate_refresh_token()

    await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
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
    presented_hash = hash_refresh_token(body.refresh_token)
    token_row = await get_refresh_token_by_hash(session, presented_hash)

    if token_row is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    now = datetime.now(timezone.utc)

    if token_row.revoked:
        # No successor recorded: this row was revoked directly (logout,
        # or a previous reuse that revoked the whole family), not
        # rotated. Nothing here is eligible for the grace window.
        if token_row.replaced_by is None:
            raise HTTPException(status_code=401, detail="Refresh token revoked")

        successor = await get_refresh_token_by_id(session, token_row.replaced_by)

        # Only the *direct* predecessor of the currently-active token
        # gets grace-window leniency -- i.e. its successor must itself
        # still be the active (unrevoked) tip of the chain. Reuse of
        # anything further back always revokes the family, regardless
        # of timing.
        is_direct_predecessor = successor is not None and not successor.revoked

        rotated_at = token_row.updated_at or token_row.created_at
        within_grace_window = (
            now - rotated_at
        ).total_seconds() <= settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS

        if is_direct_predecessor and within_grace_window:
            cached = await get_cached_refresh_grace_pair(presented_hash)
            if cached is not None:
                return TokenResponse(**cached)
            # Cache entry expired/evicted -- ambiguous, so fail closed
            # for this request without punishing the whole family: a
            # concurrent legitimate refresh may simply have to retry.
            raise HTTPException(
                status_code=401, detail="Refresh token already used"
            )

        # Reuse outside the grace window, or of a token older than the
        # direct predecessor: treat as a stolen/replayed token and kill
        # every token in the family.
        await revoke_refresh_token_family(session, token_row.family_id)
        raise HTTPException(status_code=401, detail="Refresh token already used")

    if token_row.expires_at < now:
        # The token's own expiry lapsed without a refresh in time. Not
        # itself a sign of reuse/theft, so unlike the branches above
        # this doesn't revoke the family -- it's just an ordinary
        # "please log in again".
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = await session.get(User, token_row.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")

    new_access = create_access_token(str(user.id))
    new_refresh, new_expires_at = generate_refresh_token()

    new_token_row = await store_refresh_token(
        session,
        user_id=user.id,
        family_id=token_row.family_id,
        token_hash=hash_refresh_token(new_refresh),
        expires_at=new_expires_at,
        ip_address=request.client.host if request.client else None,
    )
    await mark_refresh_token_replaced(session, token_row, new_token_row.id)

    response = TokenResponse(access_token=new_access, refresh_token=new_refresh)
    await cache_refresh_grace_pair(
        presented_hash,
        response.model_dump(),
        ttl_seconds=settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS,
    )
    return response


@router.post("/logout", status_code=204)
async def logout(
    user: Annotated[User, Depends(get_current_user)],
    jti: Annotated[str | None, Depends(get_current_jti)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    body: LogoutRequest = LogoutRequest(),
):
    # Only the family tied to *this* session's refresh token is
    # revoked -- not every refresh token the user holds. Logging out on
    # one device/tab must not knock the user out of a different one.
    # Use /auth/logout-all for that.
    if body.refresh_token:
        token_hash = hash_refresh_token(body.refresh_token)
        token_row = await get_refresh_token_by_hash(session, token_hash)
        if token_row is not None and token_row.user_id == user.id:
            await revoke_refresh_token_family(session, token_row.family_id)

    # Without this, the access token used to call /logout stays valid
    # for the rest of its natural lifetime -- logging out wouldn't
    # actually revoke the thing that grants access.
    if jti:
        await block_token(jti)


@router.post("/logout-all", status_code=204)
async def logout_all(
    user: Annotated[User, Depends(get_current_user)],
    jti: Annotated[str | None, Depends(get_current_jti)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """End every session for this user, on every client/device."""
    await revoke_user_refresh_tokens(session, user.id)
    # Blanket-block every access token this user currently holds, not
    # just the one used to call this endpoint -- otherwise another
    # device's still-valid access token would keep working until it
    # naturally expires, even though its refresh token is now dead.
    await block_all_user_tokens(str(user.id))
    if jti:
        await block_token(jti)


@router.get("/me", response_model=UserResponse)
async def me(user: Annotated[User, Depends(get_current_user)]):
    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
        organizations=[
            OrganizationMembershipResponse(
                id=m.organization.id, name=m.organization.name, role=m.role
            )
            for m in user.memberships
        ],
    )
