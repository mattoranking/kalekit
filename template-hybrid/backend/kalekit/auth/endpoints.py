from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from redis.exceptions import RedisError
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
    create_verification_token,
    find_user_by_email,
    get_refresh_token_by_hash,
    get_refresh_token_by_id,
    get_valid_verification_token,
    invalidate_user_verification_tokens,
    lock_refresh_token_by_hash,
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
from kalekit.auth.service import (
    create_access_token,
    generate_refresh_token,
    generate_verification_token,
    hash_refresh_token,
    hash_verification_token,
    verification_token_expiry,
    verify_password,
)
from kalekit.config import settings
from kalekit.models.organization import MemberRole
from kalekit.models.user import User
from kalekit.organization.repository import add_member, create_organization
from kalekit.organization.schemas import OrganizationMembershipResponse
from kalekit.postgres import get_db_session
from kalekit.redis import get_redis
from kalekit.utils.email import get_email_sender, send_verification_email
from kalekit.utils.rate_limit import check_and_increment, rate_limit_fails_open

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    body: RegisterRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    background_tasks: BackgroundTasks,
):
    # Surface a deployment with no real email provider as a request-time
    # failure before anything is written (see get_email_sender), instead
    # of a registration that silently never sends its verification link.
    get_email_sender()

    existing = await find_user_by_email(session, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    # Password sign-ups always start unverified -- verification proves
    # the registrant controls this mailbox, which is what lets OAuth
    # account-linking trust the email later (see oauth/repository.py).
    user = await create_user(session, body.email, body.password, email_verified=False)

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

    await _issue_and_queue_verification_email(session, background_tasks, user)

    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        email_verified=user.email_verified,
        created_at=user.created_at,
        organizations=[
            OrganizationMembershipResponse(
                id=organization.id, name=organization.name, role=MemberRole.owner
            )
        ],
    )


async def _issue_and_queue_verification_email(
    session: AsyncSession, background_tasks: BackgroundTasks, user: User
) -> None:
    """Persist a fresh verification token and email the link.

    The send is deferred to a background task, the same way invitations
    are, so it runs after the response is built. FastAPI runs background
    tasks before the request's session dependency commits, so the email
    goes out just before the token row is committed.
    """
    assert user.email is not None
    raw_token = generate_verification_token()
    await create_verification_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=verification_token_expiry(),
    )
    background_tasks.add_task(send_verification_email, to=user.email, token=raw_token)


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    user = await find_user_by_email(session, body.email)
    password_hash = user.password_hash if user else None
    # OAuth-only accounts have no password hash; the hasher can't verify
    # against None, so reject them with the same 401 as a wrong password.
    if (
        not user
        or not password_hash
        or not verify_password(body.password, password_hash)
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
    if settings.REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN and not user.email_verified:
        raise HTTPException(status_code=403, detail="Email verification required")

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
    # Locked (SELECT ... FOR UPDATE), not the plain lookup: this path
    # rotates the row, so two truly concurrent refreshes presenting
    # the same token must be serialized here -- see
    # lock_refresh_token_by_hash's docstring.
    token_row = await lock_refresh_token_by_hash(session, presented_hash)

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
                try:
                    return TokenResponse(**cached)
                except (TypeError, ValidationError):
                    # The cache entry parsed as JSON and is a dict (see
                    # get_cached_refresh_grace_pair), but doesn't have
                    # the shape TokenResponse expects -- corrupted or
                    # unexpected Redis data. Fall through to the same
                    # "cache entry expired/evicted" handling below
                    # rather than letting an unhandled validation error
                    # 500 this request; this should never happen in
                    # practice, since the only writer
                    # (cache_refresh_grace_pair) always stores a real
                    # TokenResponse.model_dump().
                    pass
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
        # get_db_session rolls back on any exception, which would undo the
        # revoke above (#112). Commit it before raising.
        await session.commit()
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
    # Awaited here, inline -- deliberately *before* the request-scoped
    # commit (get_db_session commits only after this endpoint returns),
    # not deferred via BackgroundTasks. A BackgroundTasks deferral looks
    # appealing (it's the pattern organization/endpoints.py uses for
    # invitation emails, so the cache write only happens once the new
    # refresh-token row is durably committed) but it's wrong here: this
    # rotation path takes a row lock (lock_refresh_token_by_hash), and
    # it's the commit itself that releases that lock. A second,
    # legitimately-concurrent request blocked on the lock can unblock
    # the instant this request's commit happens -- which is strictly
    # *before* a deferred BackgroundTask would run (those only fire
    # after the response is sent). That request would then find no
    # cached pair yet and wrongly 401 instead of getting the shared
    # pair, defeating the grace window's actual purpose. Writing here,
    # before commit/lock-release, guarantees the cache is populated by
    # the time any blocked concurrent request can possibly see the
    # rotated row. This does re-accept a narrower risk (a commit
    # failure *after* this write leaves a phantom, never-persisted
    # cache entry) -- same trade-off template-rbac's shipped reference
    # implementation already makes, and self-correcting: that phantom
    # token was never stored, so its own next use 401s normally. See
    # PR #90 round 3 vs round 4 review discussion / issue #91.
    await cache_refresh_grace_pair(
        presented_hash,
        response.model_dump(),
        ttl_seconds=settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS,
    )
    return response


logger = structlog.get_logger()


def _revocation_unavailable(event: str) -> JSONResponse:
    """A clean 503 for a Redis failure while blocking a revoked token (#122).

    Redis is the only home of the access-token blocklist, so when the
    block can't be written the revoked token would stay usable until it
    expires. Fail closed: tell the client the sign-out did not complete
    so it retries. The database revoke that ran just before is
    idempotent, so a retry is safe.

    Returned rather than raised, on purpose: an HTTPException would run
    get_db_session's rollback and undo the database revoke, while a
    normal response lets it commit. Call from inside an `except
    RedisError` block so the traceback is attached to the log.
    """
    logger.warning(event, exc_info=True)
    return JSONResponse(
        status_code=503,
        content={"detail": "Could not complete sign-out, please try again"},
    )


@router.post("/logout", status_code=204)
async def logout(
    user: Annotated[User, Depends(get_current_user)],
    jti: Annotated[str | None, Depends(get_current_jti)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    body: LogoutRequest | None = None,
):
    # `body` defaults to None, not a shared LogoutRequest() instance --
    # a mutable Pydantic model as a function default is evaluated once
    # at import time and reused across every request that omits a
    # body, which is a footgun if anything ever comes to mutate it.
    # A pre-existing hybrid client that calls /auth/logout with no
    # body at all (only an access token) must keep working -- that's
    # why this stays optional rather than a required LogoutRequest,
    # unlike RBAC's more recent logout() signature.
    #
    # Only the family tied to *this* session's refresh token is
    # revoked -- not every refresh token the user holds. Logging out on
    # one device/tab must not knock the user out of a different one.
    # Use /auth/logout-all for that.
    if body is not None and body.refresh_token:
        token_hash = hash_refresh_token(body.refresh_token)
        token_row = await get_refresh_token_by_hash(session, token_hash)
        if token_row is not None and token_row.user_id == user.id:
            await revoke_refresh_token_family(session, token_row.family_id)

    # Without this, the access token used to call /logout stays valid
    # for the rest of its natural lifetime -- logging out wouldn't
    # actually revoke the thing that grants access.
    if jti:
        try:
            await block_token(jti)
        except RedisError:
            return _revocation_unavailable("logout_block_token_failed")


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
    try:
        await block_all_user_tokens(str(user.id))
        if jti:
            await block_token(jti)
    except RedisError:
        return _revocation_unavailable("logout_all_block_failed")


@router.get("/me", response_model=UserResponse)
async def me(user: Annotated[User, Depends(get_current_user)]):
    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        email_verified=user.email_verified,
        created_at=user.created_at,
        organizations=[
            OrganizationMembershipResponse(
                id=m.organization.id, name=m.organization.name, role=m.role
            )
            for m in user.memberships
        ],
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
    background_tasks: BackgroundTasks,
):
    if user.email_verified:
        return MessageResponse(detail="Email already verified")
    if user.email is None:
        # An OAuth user whose provider gave no email has nowhere to send a
        # link to.
        raise HTTPException(status_code=400, detail="Account has no email address")

    get_email_sender()

    with rate_limit_fails_open("resend_verification"):
        r = await get_redis()
        allowed = await check_and_increment(
            r,
            f"resend_verification_rate:user:{user.id}",
            limit=settings.RESEND_VERIFICATION_RATE_LIMIT_PER_USER,
            window_seconds=settings.RESEND_VERIFICATION_RATE_LIMIT_WINDOW_SECONDS,
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many verification emails, try again later",
            )

    # Open to any authenticated user regardless of require_verified_email:
    # an unverified user still needs a way to request a fresh link.
    await invalidate_user_verification_tokens(session, user.id)
    await _issue_and_queue_verification_email(session, background_tasks, user)

    return MessageResponse(detail="Verification email sent")
