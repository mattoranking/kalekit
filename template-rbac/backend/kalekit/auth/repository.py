import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
    family_id: uuid.UUID | None = None,
    device_info: str | None = None,
    ip_address: str | None = None,
) -> RefreshToken:
    """Insert a new refresh token row.

    `family_id` should be passed explicitly whenever this token is a
    rotation of an existing one (carry the predecessor's family_id
    forward); omit it only when starting a brand-new family (login,
    OAuth callback), in which case the column default mints a fresh one.
    """
    token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        device_info=device_info,
        ip_address=ip_address,
        **({"family_id": family_id} if family_id is not None else {}),
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


async def list_user_sessions(
    session: AsyncSession, user_id: uuid.UUID
) -> list[list[RefreshToken]]:
    """Group the user's refresh tokens by family, one group per active
    session (families with no unrevoked token left are dead sessions
    and are excluded). Each group is sorted oldest-first, so
    group[0].created_at is the session's start and group[-1] is its
    most recent token (last_used_at, device_info, ip_address).
    """
    result = await session.execute(
        select(RefreshToken)
        .where(RefreshToken.user_id == user_id)
        .order_by(RefreshToken.family_id, RefreshToken.created_at)
    )
    families: dict[uuid.UUID, list[RefreshToken]] = {}
    for token in result.scalars():
        families.setdefault(token.family_id, []).append(token)

    return [
        tokens
        for tokens in families.values()
        if any(not t.revoked for t in tokens)
    ]
