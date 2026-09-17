import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.client_type import ClientType
from kalekit.auth.dependencies import (
    get_current_jti,
    get_current_session_id,
    get_current_user,
)
from kalekit.auth.permissions import (
    block_all_user_tokens,
    block_family_tokens,
    block_token,
    cache_refresh_grace_pair,
    get_cached_refresh_grace_pair,
    get_scopes_for_roles,
)
from kalekit.auth.repository import (
    create_user,
    create_verification_token,
    find_user_by_email,
    get_family_owner,
    get_refresh_token_by_hash,
    get_refresh_token_by_id,
    get_valid_verification_token,
    invalidate_user_verification_tokens,
    list_user_sessions,
    mark_refresh_token_replaced,
    mark_verification_token_used,
    revoke_refresh_token_family,
    revoke_user_refresh_tokens,
    revoke_user_refresh_tokens_except_family,
    store_refresh_token,
    update_user_password,
)
from kalekit.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    SessionListResponse,
    SessionResponse,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from kalekit.auth.seed import assign_role, ensure_default_roles
from kalekit.auth.service import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    device_info_from_user_agent,
    generate_refresh_token,
    generate_verification_token,
    hash_refresh_token,
    hash_verification_token,
    verification_token_expiry,
    verify_and_upgrade_password,
    verify_password,
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
    #
    # The email-existence check above doesn't stop two simultaneous
    # registrations for the same address from both passing it and both
    # reaching this insert -- `User.email` is DB-unique, so the loser
    # hits an IntegrityError. Catch it (rolling back only this savepoint,
    # not the whole request's transaction) and report the same clean 409
    # the sequential case gets, instead of letting it bubble up as a 500.
    try:
        async with session.begin_nested():
            user = await create_user(
                session, body.email, body.password, email_verified=False
            )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="Email already registered"
        ) from exc

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
    if settings.REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN and not user.email_verified:
        raise HTTPException(status_code=403, detail="Email verification required")

    # Transparently move a legacy (pre-pwdlib) bcrypt hash onto Argon2
    # now that we know the plaintext password -- no forced reset needed.
    # Done only once every other check has passed, so a login that's
    # ultimately rejected never mutates the stored hash as a side effect.
    if upgraded_hash is not None:
        user.password_hash = upgraded_hash
        await session.flush()

    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    refresh_token, expires_at = generate_refresh_token(body.client)

    # Store the refresh token first so its (auto-generated) family_id
    # exists to stamp the access token's `sid` claim with -- that's
    # what ties this access token to the session /auth/sessions and
    # DELETE /auth/sessions/{id} operate on. `family_created_at` is left
    # unset so the column default ("now") applies -- this is the start
    # of a brand-new session.
    token_row = await store_refresh_token(
        session,
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
        expires_at=expires_at,
        client=body.client.value,
        ip_address=request.client.host if request.client else None,
        device_info=device_info_from_user_agent(request.headers.get("user-agent")),
    )
    access_token = create_access_token(
        str(user.id),
        list(scopes),
        client=body.client,
        session_id=str(token_row.family_id),
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
        # every token in the family. Also block any access token
        # already minted under this family -- without this, a
        # detected-stolen session's still-live access token (issued at
        # the last legitimate login/refresh) would keep working for
        # the rest of its natural lifetime despite the family being
        # revoked, undercutting the whole point of reuse detection.
        await revoke_refresh_token_family(session, token_row.family_id)
        await block_family_tokens(str(token_row.family_id))
        raise HTTPException(status_code=401, detail="Refresh token already used")

    if token_row.expires_at < now:
        # The idle timeout: this token's own sliding expiry lapsed
        # without a refresh in time. Not itself a sign of reuse/theft,
        # so unlike the branches above this doesn't revoke the family
        # -- it's just an ordinary "please log in again".
        raise HTTPException(status_code=401, detail="Refresh token expired")

    client = ClientType(token_row.client)

    # The absolute timeout: a session ends this long after the
    # *original* login, however active it's been, measured from
    # family_created_at (which rotation -- below -- carries forward
    # unchanged, unlike expires_at). None means no cutoff for this
    # client (the default for web/mobile). Checked before minting
    # anything new, and revokes the family the same way reuse detection
    # does -- an absolute-timeout session is just as dead as one that
    # went idle or was explicitly revoked.
    absolute_timeout = settings.session_absolute_timeout(client)
    if (
        absolute_timeout is not None
        and now - token_row.family_created_at > absolute_timeout
    ):
        await revoke_refresh_token_family(session, token_row.family_id)
        await block_family_tokens(str(token_row.family_id))
        raise HTTPException(status_code=401, detail="Session expired")

    user = await session.get(User, token_row.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")

    roles = [ur.role.name for ur in user.roles]
    scopes = await get_scopes_for_roles(session, roles)
    new_access = create_access_token(
        str(user.id), list(scopes), client=client, session_id=str(token_row.family_id)
    )
    new_refresh, new_expires_at = generate_refresh_token(client)

    new_token_row = await store_refresh_token(
        session,
        user_id=user.id,
        family_id=token_row.family_id,
        family_created_at=token_row.family_created_at,
        token_hash=hash_refresh_token(new_refresh),
        expires_at=new_expires_at,
        client=token_row.client,
        ip_address=request.client.host if request.client else None,
        device_info=device_info_from_user_agent(request.headers.get("user-agent")),
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


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    user: Annotated[User, Depends(get_current_user)],
    session_id: Annotated[str | None, Depends(get_current_session_id)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """List the caller's active sessions (one entry per live token
    family), most recently used first, with the one behind this
    request's own access token marked `is_current`."""
    sessions = await list_user_sessions(session, user.id)
    items = [
        SessionResponse(
            id=summary.family_id,
            device_info=summary.device_info,
            ip_address=summary.ip_address,
            created_at=summary.created_at,
            last_used_at=summary.last_used_at,
            is_current=session_id is not None
            and str(summary.family_id) == session_id,
        )
        for summary in sessions
    ]
    items.sort(key=lambda s: s.last_used_at, reverse=True)
    return SessionListResponse(items=items)


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(
    session_id: uuid.UUID,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Revoke one of the caller's own sessions (a refresh token
    family). 404s for a family that doesn't exist *or* belongs to
    another user -- same response either way, so this can't be used to
    probe whether some other user's session id exists."""
    owner_id = await get_family_owner(session, session_id)
    if owner_id is None or owner_id != user.id:
        raise HTTPException(status_code=404, detail="Session not found")

    await revoke_refresh_token_family(session, session_id)
    # The refresh token is dead, but any access token already minted
    # under this family is still valid for the rest of its natural
    # lifetime unless explicitly blocked -- this is what makes
    # revocation take effect immediately instead of up to
    # ACCESS_TOKEN_EXPIRE_MINUTES later.
    await block_family_tokens(str(session_id))


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    body: ChangePasswordRequest,
    user: Annotated[User, Depends(get_current_user)],
    session_id: Annotated[str | None, Depends(get_current_session_id)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Change the caller's password and sign out every other session,
    keeping the one this request was made from alive -- a changed
    password is meaningless if a session opened under the old one
    (e.g. by whoever the password is being changed *because of*) is
    still live elsewhere."""
    if not user.password_hash or not verify_password(
        body.current_password, user.password_hash
    ):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    await update_user_password(session, user, body.new_password)

    # `sid` is best-effort: treat a missing *or* malformed claim the
    # same way -- as "no session tied to this token" -- rather than
    # letting a bad UUID string 500 this request. The token is
    # attacker-influenceable in principle, so this has to fail closed,
    # not raise.
    try:
        keep_family_id = uuid.UUID(session_id) if session_id else None
    except ValueError:
        keep_family_id = None

    revoked_families = await revoke_user_refresh_tokens_except_family(
        session, user.id, keep_family_id
    )
    for family_id in revoked_families:
        await block_family_tokens(str(family_id))

    if keep_family_id is None:
        # The caller's own access token has no (usable) session id, so
        # there's no family id to spare it from being blocked above --
        # every family (including whichever one minted this very
        # token) was just revoked. Falling back to block_all_user_tokens
        # fails closed: the promise is "everywhere else is signed out
        # immediately", and leaving this access token usable until its
        # natural expiry would quietly break that for this edge case
        # (tokens minted before `sid` existed, or issued outside
        # login/refresh/OAuth). This does mean the *current* request's
        # own token also becomes unusable next call, since we can't
        # tell it apart from the others without a session id -- an
        # acceptable trade next to leaving a live token unrevoked.
        await block_all_user_tokens(str(user.id))

    return MessageResponse(detail="Password changed")


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
