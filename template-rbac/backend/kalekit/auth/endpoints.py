from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import get_current_jti, get_current_user
from kalekit.auth.permissions import (
    block_all_user_tokens,
    block_token,
    cache_refresh_grace_pair,
    get_cached_refresh_grace_pair,
    get_scopes_for_roles,
)
from kalekit.auth.repository import (
    create_user,
    create_verification_token,
    find_user_by_email,
    get_refresh_token_by_hash,
    get_refresh_token_by_id,
    get_valid_verification_token,
    invalidate_user_verification_tokens,
    mark_refresh_token_replaced,
    mark_verification_token_used,
    revoke_refresh_token_family,
    revoke_user_refresh_tokens,
    store_refresh_token,
)
from kalekit.auth.schemas import (
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from kalekit.auth.seed import assign_role, ensure_default_roles
from kalekit.auth.service import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    generate_refresh_token,
    generate_verification_token,
    hash_refresh_token,
    hash_verification_token,
    verification_token_expiry,
    verify_and_upgrade_password,
)
from kalekit.config import settings
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.utils.email import send_verification_email

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

    # Password sign-ups always start unverified -- verification proves
    # the registrant actually controls this mailbox, which is what lets
    # OAuth account-linking trust the email later (see oauth/repository.py).
    user = await create_user(session, body.email, body.password, email_verified=False)

    # Every self-signup gets the default role -- there is no first-user
    # admin rule. Promoting an admin is a deliberate, out-of-band act via
    # `python -m kalekit.cli create-admin` (see kalekit/cli.py), not an
    # accident of registration order.
    visitor_role, _ = await ensure_default_roles(session)
    await assign_role(session, user, visitor_role)

    await _issue_and_send_verification_token(session, user)

    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        email_verified=user.email_verified,
        created_at=user.created_at,
        roles=[visitor_role.name],
    )


async def _issue_and_send_verification_token(
    session: AsyncSession, user: User
) -> None:
    raw_token = generate_verification_token()
    await create_verification_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=verification_token_expiry(),
    )
    await send_verification_email(to=user.email, token=raw_token)


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    user = await find_user_by_email(session, body.email)

    # Always run a hash verification, even when the email doesn't exist,
    # so the response timing for "unknown email" and "wrong password" is
    # indistinguishable -- otherwise the (deliberately slow) bcrypt check
    # being skipped for unknown emails would let an attacker enumerate
    # registered accounts by measuring response latency.
    password_hash = (user.password_hash if user else None) or DUMMY_PASSWORD_HASH
    password_valid, upgraded_hash = verify_and_upgrade_password(
        body.password, password_hash
    )

    if not user or not password_valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")

    # Transparently move a legacy (pre-pwdlib) bcrypt hash onto Argon2
    # now that we know the plaintext password -- no forced reset needed.
    if upgraded_hash is not None:
        user.password_hash = upgraded_hash
        await session.flush()
    if settings.REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN and not user.email_verified:
        raise HTTPException(status_code=403, detail="Email verification required")

    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    access_token = create_access_token(str(user.id), list(scopes))
    refresh_token, expires_at = generate_refresh_token()

    await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
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
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = await session.get(User, token_row.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")

    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    new_access = create_access_token(str(user.id), list(scopes))
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
    body: LogoutRequest,
):
    # Only the family tied to *this* session's refresh token is
    # revoked -- not every refresh token the user holds. Web, mobile,
    # and any other signed-in device/tab share one users table, so
    # revoking all of them here would log the user out everywhere
    # just because one client logged out. Use /auth/logout-all for
    # that.
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
        email_verified=user.email_verified,
        created_at=user.created_at,
        roles=[ur.role.name for ur in user.roles],
    )


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    body: VerifyEmailRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    token = await get_valid_verification_token(
        session, hash_verification_token(body.token)
    )
    if not token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired verification token"
        )

    user = await session.get(User, token.user_id)
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired verification token"
        )

    user.email_verified = True
    await mark_verification_token_used(session, token)

    return MessageResponse(detail="Email verified")


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    if user.email_verified:
        return MessageResponse(detail="Email already verified")

    # Reachable while unverified even when REQUIRE_EMAIL_VERIFICATION_
    # BEFORE_LOGIN is off, and it's the escape hatch for the case where
    # login is gated on verification too -- an unverified user still
    # needs a way to request a fresh link, so this stays open to any
    # authenticated user regardless of require_verified_email.
    await invalidate_user_verification_tokens(session, user.id)
    await _issue_and_send_verification_token(session, user)

    return MessageResponse(detail="Verification email sent")
