import uuid
from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.client_type import ClientType
from kalekit.auth.dependencies import (
    get_current_jti,
    get_current_session_id,
    get_current_user,
    require_recent_auth,
)
from kalekit.auth.permissions import (
    block_all_user_tokens,
    block_family_tokens,
    block_token,
    cache_refresh_grace_pair,
    consume_oauth_reauth_ticket,
    get_cached_refresh_grace_pair,
    get_redis,
    get_scopes_for_roles,
)
from kalekit.auth.repository import (
    claim_password_reset_token,
    create_password_reset_token,
    create_user,
    create_verification_token,
    find_user_by_email,
    get_active_refresh_token_by_family,
    get_family_owner,
    get_refresh_token_by_hash,
    get_refresh_token_by_hash_for_update,
    get_refresh_token_by_id,
    get_valid_verification_token,
    invalidate_user_password_reset_tokens,
    invalidate_user_verification_tokens,
    list_user_sessions,
    mark_refresh_token_replaced,
    mark_session_reauthenticated,
    mark_verification_token_used,
    revoke_refresh_token_family,
    revoke_user_refresh_tokens,
    revoke_user_refresh_tokens_except_family,
    store_refresh_token,
    update_user_password,
)
from kalekit.auth.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    ReauthenticateRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
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
    password_reset_token_expiry,
    verification_token_expiry,
    verify_password,
)
from kalekit.config import settings
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.utils.email import send_password_reset_email, send_verification_email
from kalekit.utils.rate_limit import (
    bounded_identifier,
    check_and_increment,
    get_client_ip,
    rate_limit_fails_open,
)

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


def _rate_limited(retry_after_seconds: int) -> HTTPException:
    """A 429 carrying `Retry-After`, per issue #18's acceptance
    criteria. `retry_after_seconds` should come from the tripped key's
    Redis TTL; guarded to at least 1 since a key can (rarely) read back
    a TTL of 0 or -1 right at expiry/recovery."""
    retry_after = max(retry_after_seconds, 1)
    return HTTPException(
        status_code=429,
        detail="Too many requests, try again later",
        headers={"Retry-After": str(retry_after)},
    )


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    body: RegisterRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    if settings.RATE_LIMIT_ENABLED:
        with rate_limit_fails_open("register"):
            r = await get_redis()
            ip_key = f"register_rate:ip:{get_client_ip(request)}"
            allowed = await check_and_increment(
                r,
                ip_key,
                limit=settings.REGISTER_RATE_LIMIT_PER_IP,
                window_seconds=settings.REGISTER_RATE_LIMIT_WINDOW_SECONDS,
            )
            if not allowed:
                raise _rate_limited(await r.ttl(ip_key))

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
    r = None
    # Keyed on the submitted email, lowercased -- not on the resolved
    # user id -- so an unknown email is throttled exactly like a real
    # one; otherwise this limit itself becomes an account-enumeration
    # oracle. (find_user_by_email itself does an exact, non-lowercased
    # match -- this app doesn't normalize email casing anywhere else --
    # so the lowercasing here is purely to keep this counter from being
    # split across multiple keys by a caller who varies casing between
    # requests targeting the same account.)
    account_key = f"login_rate:account:{bounded_identifier(body.email.lower())}"
    if settings.RATE_LIMIT_ENABLED:
        with rate_limit_fails_open("login"):
            r = await get_redis()
            ip_key = f"login_rate:ip:{get_client_ip(request)}"
            ip_allowed = await check_and_increment(
                r,
                ip_key,
                limit=settings.LOGIN_RATE_LIMIT_PER_IP,
                window_seconds=settings.LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS,
            )
            if not ip_allowed:
                raise _rate_limited(await r.ttl(ip_key))

            # Peek (don't increment) the account's failure count -- only an
            # actual failed attempt below should consume this budget, so a
            # request that goes on to succeed must not have already spent
            # a unit of it just by arriving.
            current_failures = await r.get(account_key)
            if current_failures:
                account_ttl = await r.ttl(account_key)
                if account_ttl == -1:
                    # Same TTL-recovery this key would otherwise only get
                    # from check_and_increment (see utils/rate_limit.py) --
                    # but this peek path never calls that, so without this
                    # a key that lost its expiry (e.g. a crash between a
                    # prior INCR and its EXPIRE) would block this account
                    # forever instead of resetting after the window.
                    account_ttl = settings.LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS
                    await r.expire(account_key, account_ttl)
                if int(current_failures) >= settings.LOGIN_RATE_LIMIT_PER_ACCOUNT:
                    raise _rate_limited(account_ttl)

    user = await find_user_by_email(session, body.email)

    # Always run a hash verification, even when the email doesn't exist,
    # so the response timing for "unknown email" and "wrong password" is
    # indistinguishable -- otherwise the (deliberately slow) Argon2 check
    # being skipped for unknown emails would let an attacker enumerate
    # registered accounts by measuring response latency.
    password_hash = (user.password_hash if user else None) or DUMMY_PASSWORD_HASH
    password_valid = verify_password(body.password, password_hash)

    if not user or not password_valid:
        if r is not None:
            with rate_limit_fails_open("login"):
                await check_and_increment(
                    r,
                    account_key,
                    limit=settings.LOGIN_RATE_LIMIT_PER_ACCOUNT,
                    window_seconds=settings.LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS,
                )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
    if settings.REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN and not user.email_verified:
        raise HTTPException(status_code=403, detail="Email verification required")

    if r is not None:
        # A successful login clears any accumulated failure count for
        # this account -- the threshold is meant to slow down guessing,
        # not to keep locking out someone who's now proven they have
        # the right password.
        with rate_limit_fails_open("login"):
            await r.delete(account_key)

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
        client=body.client,
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


logger = structlog.get_logger()


def _revocation_unavailable(event: str) -> JSONResponse:
    """A clean 503 for a Redis failure while blocking a revoked token (#108).

    Redis is the only home of the access-token blocklist, so when the
    block can't be written the revoked token would stay usable until it
    expires. Fail closed: tell the client the sign-out/revocation did
    not complete so it retries. The database revoke that ran just before
    is idempotent, so a retry is safe.

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


def _reauth_unavailable() -> HTTPException:
    """A clean 503 when the re-auth ticket can't be read from Redis (#108).

    The ticket lives only in Redis, so there is nothing to fall back to;
    same direction as the OAuth state paths (#99). Call from inside an
    `except RedisError` block.
    """
    logger.warning("oauth_reauth_ticket_consume_failed", exc_info=True)
    return HTTPException(
        status_code=503, detail="OAuth sign-in is temporarily unavailable"
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    presented_hash = hash_refresh_token(body.refresh_token)
    # Row-locked: the lock is held until get_db_session commits, which
    # serializes concurrent refreshes of the same token. That is also
    # why the grace-pair cache write at the end of this function must
    # stay inline (awaited before returning/commit), never deferred to
    # BackgroundTasks: a blocked second request wakes the instant we
    # commit and must already find the cached pair.
    token_row = await get_refresh_token_by_hash_for_update(session, presented_hash)

    if token_row is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if settings.RATE_LIMIT_ENABLED:
        with rate_limit_fails_open("refresh"):
            # Keyed per session (the refresh token family), not per IP -- a
            # session legitimately moves across IPs (mobile networks, VPNs),
            # and the presented token is already the unguessable secret.
            # This just caps how fast one session can spin through
            # refreshes, e.g. a buggy client stuck in a retry loop.
            r = await get_redis()
            session_key = f"refresh_rate:session:{token_row.family_id}"
            session_allowed = await check_and_increment(
                r,
                session_key,
                limit=settings.REFRESH_RATE_LIMIT_PER_SESSION,
                window_seconds=settings.REFRESH_RATE_LIMIT_WINDOW_SECONDS,
            )
            if not session_allowed:
                raise _rate_limited(await r.ttl(session_key))

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
        try:
            await block_family_tokens(str(token_row.family_id))
        except RedisError:
            # The family is revoked in the database, but the live access
            # token can't be blocked: fail closed (#108) instead of an
            # unhandled 500.
            return _revocation_unavailable("reuse_detection_block_failed")
        raise HTTPException(status_code=401, detail="Refresh token already used")

    if token_row.expires_at < now:
        # The idle timeout: this token's own sliding expiry lapsed
        # without a refresh in time. Not itself a sign of reuse/theft,
        # so unlike the branches above this doesn't revoke the family
        # -- it's just an ordinary "please log in again".
        raise HTTPException(status_code=401, detail="Refresh token expired")

    try:
        client = ClientType(token_row.client)
    except ValueError:
        # The stored `client` isn't one of ClientType's values -- data
        # that should be unreachable through this app's own code paths
        # (store_refresh_token only ever accepts a ClientType), so
        # treat it the same as the other "this session can't be
        # trusted" cases above: fail closed with a 401 and revoke the
        # family, rather than let an unhandled ValueError surface as a
        # 500. See the round-2 Copilot review on PR #75.
        await revoke_refresh_token_family(session, token_row.family_id)
        await block_family_tokens(str(token_row.family_id))
        raise HTTPException(status_code=401, detail="Refresh token invalid")

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
        auth_time=token_row.auth_time,
        token_hash=hash_refresh_token(new_refresh),
        expires_at=new_expires_at,
        client=client,
        ip_address=request.client.host if request.client else None,
        device_info=device_info_from_user_agent(request.headers.get("user-agent")),
    )
    await mark_refresh_token_replaced(session, token_row, new_token_row.id)

    response = TokenResponse(access_token=new_access, refresh_token=new_refresh)
    # Must stay inline, before commit -- see the lock note at the top.
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
    user: Annotated[User, Depends(require_recent_auth())],
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
    user: Annotated[User, Depends(require_recent_auth())],
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


@router.post("/reauthenticate", response_model=MessageResponse)
async def reauthenticate(
    body: ReauthenticateRequest,
    user: Annotated[User, Depends(get_current_user)],
    session_id: Annotated[str | None, Depends(get_current_session_id)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Step-up re-authentication (#16): prove identity again, right now,
    without ending or rotating the caller's existing session -- this is
    what lets `require_recent_auth`-gated actions succeed again within
    the freshness window, no new token pair needed.

    Deliberately does NOT use `require_recent_auth` itself (that would
    be circular -- the whole point is to *establish* a recent auth_time,
    not require one already exists) and instead depends directly on
    `get_current_user`, same as every other authenticated-but-not-yet-
    stepped-up endpoint.
    """
    # Validate there's an active session to update *before* checking
    # either credential -- in particular before consuming the OAuth
    # ticket below, which is single-use. Checking this first means a
    # missing/expired/malformed session never burns the caller's ticket
    # on a request that was going to fail anyway; they can retry the
    # (still-valid) ticket once they have a real session, instead of
    # being forced to redo the whole provider re-login.
    #
    # `sid` is required here (unlike change-password's best-effort
    # handling): there's no "fall back to blocking everything" option
    # for advancing a session's auth_time -- without a real family to
    # update, there is nothing to step up, so fail closed with a plain
    # 400 rather than silently no-op.
    try:
        family_id = uuid.UUID(session_id) if session_id else None
    except ValueError:
        family_id = None
    if family_id is None:
        raise HTTPException(
            status_code=400, detail="No active session to re-authenticate"
        )

    token_row = await get_active_refresh_token_by_family(session, family_id)
    if token_row is None or token_row.user_id != user.id:
        raise HTTPException(
            status_code=400, detail="No active session to re-authenticate"
        )

    if user.password_hash is not None:
        # Explicit None-check, not truthiness: `password_hash` is
        # nullable to mean "OAuth-only, no password set" (see
        # models/user.py) -- a merely-falsy-but-non-null value (e.g. a
        # corrupted empty string) should still take the password branch
        # below rather than being silently treated as OAuth-only.
        #
        # Rate limit password guesses against this account. This is the
        # scenario step-up reauth exists to defend against in the first
        # place: an attacker holding a *stolen access token* (but not
        # the actual password) hitting this endpoint to brute-force the
        # password and then legitimately step up the hijacked session --
        # without a limit here, that would defeat #16 entirely. Keyed on
        # the authenticated user's id (not email) since, unlike /login,
        # this endpoint already requires a valid existing session --
        # there's no unauthenticated caller to avoid fingerprinting via
        # account enumeration.
        account_key = f"reauth_rate:account:{user.id}"
        r = None
        if settings.RATE_LIMIT_ENABLED:
            with rate_limit_fails_open("reauthenticate"):
                r = await get_redis()
                # Peek (don't increment) -- only an actual failed attempt
                # below should consume this budget, so a request that goes
                # on to succeed must not have already spent a unit of it
                # just by arriving. Same peek-then-increment-on-failure
                # shape as /auth/login's account limit.
                current_failures = await r.get(account_key)
                if current_failures:
                    account_ttl = await r.ttl(account_key)
                    if account_ttl == -1:
                        # Recover a key that somehow lost its expiry (e.g. a
                        # crash between a prior INCR and its EXPIRE) instead
                        # of blocking this account forever -- same TTL
                        # recovery check_and_increment does, needed here too
                        # since this peek path never calls it.
                        account_ttl = settings.REAUTH_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS
                        await r.expire(account_key, account_ttl)
                    if int(current_failures) >= settings.REAUTH_RATE_LIMIT_PER_ACCOUNT:
                        raise _rate_limited(account_ttl)

        # Password users: re-enter it, same check as change-password.
        if not body.password or not verify_password(
            body.password, user.password_hash
        ):
            if r is not None:
                with rate_limit_fails_open("reauthenticate"):
                    await check_and_increment(
                        r,
                        account_key,
                        limit=settings.REAUTH_RATE_LIMIT_PER_ACCOUNT,
                        window_seconds=(
                            settings.REAUTH_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS
                        ),
                    )
            raise HTTPException(
                status_code=401, detail="Current password is incorrect"
            )
        if r is not None:
            # A successful reauth clears any accumulated failure count
            # for this account -- the limit is meant to slow down
            # guessing, not to keep locking out someone who just proved
            # they have the right password.
            with rate_limit_fails_open("reauthenticate"):
                await r.delete(account_key)
    else:
        # OAuth-only users have no password to re-enter -- "complete a
        # fresh provider login" instead (see oauth_authorize's `reauth`
        # param and oauth_callback's ticket-minting branch). Checking
        # the ticket names *this* user (not merely that it's valid)
        # stops one browser tab's fresh OAuth login from stepping up a
        # different user's already-authenticated session.
        if not body.oauth_ticket:
            raise HTTPException(
                status_code=400,
                detail="OAuth re-authentication required for this account",
            )
        try:
            ticket_user_id = await consume_oauth_reauth_ticket(body.oauth_ticket)
        except RedisError as exc:
            raise _reauth_unavailable() from exc
        if ticket_user_id is None or ticket_user_id != str(user.id):
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired re-authentication ticket",
            )

    await mark_session_reauthenticated(session, token_row)

    return MessageResponse(detail="Re-authenticated")


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

    if settings.RATE_LIMIT_ENABLED:
        with rate_limit_fails_open("resend_verification"):
            # Per user, not per IP -- this is authenticated, and the thing
            # being protected is the mailbox getting flooded, not the
            # endpoint's throughput.
            r = await get_redis()
            user_key = f"resend_verification_rate:user:{user.id}"
            allowed = await check_and_increment(
                r,
                user_key,
                limit=settings.RESEND_VERIFICATION_RATE_LIMIT_PER_USER,
                window_seconds=settings.RESEND_VERIFICATION_RATE_LIMIT_WINDOW_SECONDS,
            )
            if not allowed:
                raise _rate_limited(await r.ttl(user_key))

    # Reachable while unverified even when REQUIRE_EMAIL_VERIFICATION_
    # BEFORE_LOGIN is off, and it's the escape hatch for the case where
    # login is gated on verification too -- an unverified user still
    # needs a way to request a fresh link, so this stays open to any
    # authenticated user regardless of require_verified_email.
    await invalidate_user_verification_tokens(session, user.id)
    await _issue_and_send_verification_token(session, user)

    return MessageResponse(detail="Verification email sent")


async def _issue_password_reset_token(session: AsyncSession, user: User) -> str:
    """Persists a fresh reset token for `user` and returns the raw
    (unhashed) value to email. Only touches the DB -- unlike
    `_issue_and_send_verification_token`, sending the email is the
    caller's job, so it can be deferred separately (see
    `forgot_password`)."""
    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )
    return raw_token


_FORGOT_PASSWORD_RESPONSE = MessageResponse(
    detail="If that email is registered, a password reset link has been sent"
)


@router.post(
    "/password/forgot", response_model=MessageResponse, status_code=202
)
async def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Always answers 202 with the same body, whether or not `email`
    belongs to a real, active account -- see `_FORGOT_PASSWORD_RESPONSE`.
    A response (status or body) that varied by account existence would
    turn this endpoint into an account-enumeration oracle, exactly the
    failure mode #17 calls out -- and so would its *timing*: a known,
    active account does strictly more work per request than an unknown
    or inactive one, and for a real (non-`ConsoleEmailSender`) provider
    the dominant term in that gap is a synchronous network call to send
    the email, not the one extra token row. That's why the email send
    below is handed to `background_tasks` instead of being awaited
    inline -- it runs only *after* this response has already gone out
    to the caller, so it can't be timed by whoever's asking (round-2
    Copilot finding on PR #93). The token itself is still written and
    committed synchronously, through the normal request-scoped session,
    before this endpoint returns -- deferring that too isn't safe here
    (this session is closed out by `get_db_session`'s own teardown
    before background tasks run, so anything needing the DB has to
    happen inline) and isn't necessary anyway: one fast, indexed INSERT
    is a far smaller residual timing signal than a network round trip,
    in the same spirit as the login endpoint's DUMMY_PASSWORD_HASH --
    substantially closing the gap, not claiming to make it disappear.
    """
    if settings.RATE_LIMIT_ENABLED:
        with rate_limit_fails_open("forgot_password"):
            r = await get_redis()
            ip_key = f"password_reset_request_rate:ip:{get_client_ip(request)}"
            ip_allowed = await check_and_increment(
                r,
                ip_key,
                limit=settings.PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_IP,
                window_seconds=settings.PASSWORD_RESET_REQUEST_RATE_LIMIT_IP_WINDOW_SECONDS,
            )
            if not ip_allowed:
                raise _rate_limited(await r.ttl(ip_key))

            # Unlike login's per-account limit (which only counts actual
            # failures), this counts *every* request against the submitted
            # email unconditionally -- there's no success/failure split
            # visible to the caller here, so an unknown email must consume
            # the same budget a real one would, or the limiter itself would
            # leak which emails are registered.
            account_key = (
                f"password_reset_request_rate:account:"
                f"{bounded_identifier(body.email.lower())}"
            )
            account_allowed = await check_and_increment(
                r,
                account_key,
                limit=settings.PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_ACCOUNT,
                window_seconds=(
                    settings.PASSWORD_RESET_REQUEST_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS
                ),
            )
            if not account_allowed:
                raise _rate_limited(await r.ttl(account_key))

    user = await find_user_by_email(session, body.email)
    # Deactivated accounts are silently skipped too -- same reasoning as
    # unknown emails, since a differing response either way would leak
    # account state through this endpoint.
    if user is not None and user.is_active:
        # Burn any outstanding reset link before issuing a fresh one, so
        # an earlier emailed link stops working once a new reset is
        # requested (mirrors resend-verification).
        await invalidate_user_password_reset_tokens(session, user.id)
        raw_token = await _issue_password_reset_token(session, user)
        background_tasks.add_task(
            send_password_reset_email, to=user.email, token=raw_token
        )

    return _FORGOT_PASSWORD_RESPONSE


@router.post("/password/reset", response_model=MessageResponse)
async def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Redeems a token minted by `/auth/password/forgot`: sets the new
    password and revokes every existing session for the account.

    Sessions are revoked unconditionally, not "all but the caller's
    own" like `/auth/change-password` -- this endpoint is unauthenticated
    (there is no session to spare), and a password reset is presumptively
    responding to a compromised account, so anything that logged in
    under the old/leaked password should be signed out.

    Also how an OAuth-only account (`password_hash` is null) gets a
    password for the first time: `update_user_password` doesn't care
    whether a hash already existed, so redeeming a reset token here
    links password login onto the account exactly like setting one
    normally would.
    """
    if settings.RATE_LIMIT_ENABLED:
        with rate_limit_fails_open("reset_password"):
            r = await get_redis()
            ip_key = f"password_reset_rate:ip:{get_client_ip(request)}"
            ip_allowed = await check_and_increment(
                r,
                ip_key,
                limit=settings.PASSWORD_RESET_RATE_LIMIT_PER_IP,
                window_seconds=settings.PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS,
            )
            if not ip_allowed:
                raise _rate_limited(await r.ttl(ip_key))

    token = await claim_password_reset_token(
        session, hash_verification_token(body.token)
    )
    if token is None:
        raise HTTPException(
            status_code=400, detail="Invalid or expired reset token"
        )

    user = await session.get(User, token.user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=400, detail="Invalid or expired reset token"
        )

    await update_user_password(session, user, body.new_password)

    # Same "sign out everywhere" pair /auth/logout-all uses: revoke
    # every refresh token family (the sessions themselves), then
    # blanket-block every access token this user currently holds so an
    # already-minted one doesn't keep working for the rest of its
    # natural lifetime despite its refresh token now being dead.
    await revoke_user_refresh_tokens(session, user.id)
    await block_all_user_tokens(str(user.id))

    return MessageResponse(detail="Password reset")
