import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.client_type import ClientType
from kalekit.auth.service import hash_password
from kalekit.models.email_verification_token import EmailVerificationToken
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.user import User


async def find_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def create_user(
    session: AsyncSession,
    email: str,
    password: str,
    *,
    email_verified: bool = False,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        email_verified=email_verified,
    )
    session.add(user)
    await session.flush()
    return user


async def update_user_password(
    session: AsyncSession, user: User, new_password: str
) -> None:
    user.password_hash = hash_password(new_password)
    await session.flush()


async def create_verification_token(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    token_hash: str,
    expires_at: datetime,
) -> EmailVerificationToken:
    token = EmailVerificationToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    session.add(token)
    await session.flush()
    return token


async def get_valid_verification_token(
    session: AsyncSession, token_hash: str
) -> EmailVerificationToken | None:
    """A token is valid iff it exists, is unused, and hasn't expired."""
    result = await session.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash == token_hash,
            EmailVerificationToken.used_at.is_(None),
        )
    )
    token = result.scalar_one_or_none()
    if token is None:
        return None
    if token.expires_at < datetime.now(timezone.utc):
        return None
    return token


async def mark_verification_token_used(
    session: AsyncSession, token: EmailVerificationToken
) -> None:
    token.used_at = datetime.now(timezone.utc)
    await session.flush()


async def invalidate_user_verification_tokens(
    session: AsyncSession, user_id: uuid.UUID
) -> None:
    """Burn any outstanding tokens before issuing a fresh one on resend,
    so an old emailed link stops working once a new one is sent."""
    result = await session.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.user_id == user_id,
            EmailVerificationToken.used_at.is_(None),
        )
    )
    now = datetime.now(timezone.utc)
    for token in result.scalars():
        token.used_at = now
    await session.flush()


async def store_refresh_token(
    session: AsyncSession,
    user_id: uuid.UUID,
    token_hash: str,
    expires_at: datetime,
    client: ClientType,
    family_id: uuid.UUID | None = None,
    family_created_at: datetime | None = None,
    device_info: str | None = None,
    ip_address: str | None = None,
) -> RefreshToken:
    """Insert a new refresh token row.

    `family_id` should be passed explicitly whenever this token is a
    rotation of an existing one (carry the predecessor's family_id
    forward); omit it only when starting a brand-new family (login,
    OAuth callback), in which case the column default mints a fresh one.

    `family_created_at` must likewise be carried forward from the
    predecessor on rotation -- it's the session's absolute start (see
    RefreshToken.family_created_at) and must never move. Omit it only
    when starting a brand-new family, where the column default ("now")
    is correct.

    `client` is a `ClientType`, not a raw string -- the DB column is a
    plain String (see RefreshToken.client), but taking a validated enum
    here rather than `str` makes "only a real client value ever reaches
    the DB" a property of this function's signature instead of
    something every caller has to remember to uphold. See #6 and the
    round-2 Copilot review on PR #75.
    """
    token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        client=client.value,
        device_info=device_info,
        ip_address=ip_address,
        **({"family_id": family_id} if family_id is not None else {}),
        **(
            {"family_created_at": family_created_at}
            if family_created_at is not None
            else {}
        ),
    )
    session.add(token)
    await session.flush()
    return token


async def get_refresh_token_by_hash(
    session: AsyncSession, token_hash: str
) -> RefreshToken | None:
    """Look up a refresh token by its sha256 hash, regardless of
    revoked/replaced state -- the caller needs to see revoked and
    already-rotated rows too, to distinguish "unknown token" from
    "token reuse" (which additionally triggers family revocation).
    """
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    return result.scalar_one_or_none()


async def get_refresh_token_by_id(
    session: AsyncSession, token_id: uuid.UUID
) -> RefreshToken | None:
    return await session.get(RefreshToken, token_id)


async def mark_refresh_token_replaced(
    session: AsyncSession,
    token: RefreshToken,
    replaced_by_id: uuid.UUID,
) -> None:
    """Rotate `token` out: revoke it and record what replaced it.

    `replaced_by` is what lets a later request tell "this is the
    direct predecessor of the currently active token, replayed within
    the grace window" apart from "this is an older, already-superseded
    token being reused".
    """
    token.revoked = True
    token.replaced_by = replaced_by_id
    await session.flush()


async def revoke_user_refresh_tokens(
    session: AsyncSession, user_id: uuid.UUID
) -> None:
    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    for token in result.scalars():
        token.revoked = True
    await session.flush()


async def revoke_refresh_token_family(
    session: AsyncSession, family_id: uuid.UUID
) -> None:
    """Reuse detection response: kill every token in the family, active
    or not, so a stolen-and-already-used token can't be leveraged
    further and the legitimate holder is forced to log in again."""
    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    for token in result.scalars():
        token.revoked = True
    await session.flush()


async def revoke_user_refresh_tokens_except_family(
    session: AsyncSession,
    user_id: uuid.UUID,
    keep_family_id: uuid.UUID | None,
) -> list[uuid.UUID]:
    """End every session the user has *except* `keep_family_id`.

    Used for "sign out everywhere else" flows (password change/reset):
    the caller's own session survives, every other active family is
    revoked. Pass `keep_family_id=None` to revoke everything (e.g. the
    caller's access token doesn't carry a session id -- fail closed
    rather than guess which family to spare).

    Returns the distinct family_ids that were revoked, so the caller
    can also block their live access tokens (see
    kalekit.auth.permissions.block_family_tokens) -- revoking the
    refresh token alone doesn't invalidate an access token still
    inside its natural lifetime.
    """
    conditions = [
        RefreshToken.user_id == user_id,
        RefreshToken.revoked == False,  # noqa: E712
    ]
    if keep_family_id is not None:
        conditions.append(RefreshToken.family_id != keep_family_id)

    result = await session.execute(select(RefreshToken).where(*conditions))
    revoked_families: set[uuid.UUID] = set()
    for token in result.scalars():
        token.revoked = True
        revoked_families.add(token.family_id)
    await session.flush()
    return list(revoked_families)


async def prune_refresh_tokens(session: AsyncSession, *, older_than_days: int) -> int:
    """Delete dead refresh-token rows (revoked, or expired) that have
    been dead for at least the given retention window.

    This is the retention half of #73: the query rewrite in
    `list_user_sessions` stops dead rows from being loaded into
    Python on every session-list request, but the `refresh_tokens`
    table itself still grows forever (a new row per rotation, never
    deleted) unless something like this is run periodically. Meant to
    be invoked out of band, e.g. `kalekit.cli prune-refresh-tokens`
    on a daily cron -- see the CLI docstring and README.

    `coalesce(updated_at, expires_at)` is the retention clock, and in
    both cases it resolves to the row's *death time* -- when it
    stopped being usable -- never its issuance time:
      - A row that was explicitly revoked or replaced gets `updated_at`
        bumped by `onupdate=utc_now` (see `mark_refresh_token_replaced`
        / `revoke_user_refresh_tokens` / `revoke_refresh_token_family`),
        so it ages out from *when it was revoked*.
      - A row that only died by natural expiry and was never otherwise
        touched has a null `updated_at`, so it falls back to
        `expires_at` and ages out from *when it expired*.
    Using `created_at` (issuance time) for that fallback instead would
    be wrong: a long-lived session's token (e.g. the 90-day web/mobile
    idle timeout, see #6) can easily have a `created_at` that's
    already further in the past than the retention window the instant
    it naturally expires, which would delete it immediately instead of
    `older_than_days` after it actually died. Only rows that are
    *currently* dead are ever deleted -- still-usable tokens are
    untouched regardless of age, since a long-lived session (rotated
    regularly) must never be pruned out from under its user.

    Raises `ValueError` if `older_than_days` is negative -- a negative
    window would make `cutoff` a *future* timestamp, so
    `retention_clock <= cutoff` would hold for nearly every already-dead
    row regardless of how recently it died (e.g. a typo'd
    `--older-than-days -5` would prune far more aggressively than
    intended, silently). `older_than_days=0` is allowed -- "prune
    anything that's dead right now" is a well-defined, if aggressive,
    policy.
    """
    if older_than_days < 0:
        raise ValueError(
            f"older_than_days must be >= 0, got {older_than_days!r}"
        )
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=older_than_days)
    retention_clock = func.coalesce(RefreshToken.updated_at, RefreshToken.expires_at)
    result = await session.execute(
        delete(RefreshToken).where(
            or_(
                RefreshToken.revoked == True,  # noqa: E712
                RefreshToken.expires_at <= now,
            ),
            # "at least older_than_days" -- a row that died exactly on
            # the cutoff boundary is eligible now, not on the next run.
            retention_clock <= cutoff,
        )
    )
    await session.flush()
    return result.rowcount or 0


async def get_family_owner(
    session: AsyncSession, family_id: uuid.UUID
) -> uuid.UUID | None:
    """The user_id that owns a token family, or None if the family
    doesn't exist -- used to check ownership before revoking a session
    without leaking whether the id belongs to someone else."""
    result = await session.execute(
        select(RefreshToken.user_id)
        .where(RefreshToken.family_id == family_id)
        .limit(1)
    )
    return result.scalar_one_or_none()


@dataclass
class SessionSummary:
    family_id: uuid.UUID
    created_at: datetime
    last_used_at: datetime
    device_info: str | None
    ip_address: str | None


async def list_user_sessions(
    session: AsyncSession, user_id: uuid.UUID
) -> list[SessionSummary]:
    """One summary per *active* session (token family): families with
    no token that's both unrevoked and unexpired are dead sessions
    (naturally expired or fully revoked) and are excluded entirely --
    a user shouldn't see a "session" in the list they can't actually
    do anything with. `created_at` is the family's absolute start
    (`family_created_at`, carried unchanged across every row in the
    family -- see RefreshToken.family_created_at -- so it doesn't
    matter whether the original row has since rotated out or expired);
    `last_used_at`/`device_info`/`ip_address` come from the most
    recent token that's still usable, not merely the most recently
    created one.

    This does the per-family grouping and usable/latest filtering in
    SQL via `DISTINCT ON`, so only one row per active family is ever
    fetched -- a user's full (potentially large, ever-growing via
    rotation) token history never has to be loaded into Python. See
    #73.

    `DISTINCT ON (family_id)` picks whichever row sorts first within
    each family per the `ORDER BY`, so the tiebreak after
    `last_used_at DESC` matters: two usable rows in the same family
    can share the exact same `last_used_at` (concurrent/rapid
    rotation, or just timestamp precision), and without a
    deterministic secondary key Postgres is free to pick either one
    arbitrarily -- which would make the reported device/IP for a
    session flicker between requests with no underlying change.
    `created_at DESC, id DESC` breaks that tie consistently in favor
    of the most recently created row (falling back to `id` only for
    the vanishingly unlikely case two rows share both timestamps).
    """
    now = datetime.now(timezone.utc)
    result = await session.execute(
        select(
            RefreshToken.family_id,
            RefreshToken.family_created_at,
            RefreshToken.last_used_at,
            RefreshToken.device_info,
            RefreshToken.ip_address,
        )
        .distinct(RefreshToken.family_id)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False,  # noqa: E712
            RefreshToken.expires_at > now,
        )
        .order_by(
            RefreshToken.family_id,
            RefreshToken.last_used_at.desc(),
            RefreshToken.created_at.desc(),
            RefreshToken.id.desc(),
        )
    )
    return [
        SessionSummary(
            family_id=row.family_id,
            created_at=row.family_created_at,
            last_used_at=row.last_used_at,
            device_info=row.device_info,
            ip_address=row.ip_address,
        )
        for row in result
    ]
