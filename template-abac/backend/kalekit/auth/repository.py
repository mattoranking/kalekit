import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.service import hash_password
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.user import User


async def find_user_by_email(session: AsyncSession, email: str | None) -> User | None:
    if email is None:
        # NULL never matches via `=` in SQL, but guard explicitly so a
        # caller never accidentally looks up "the user with no email".
        return None
    result = await session.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def create_user(session: AsyncSession, email: str, password: str) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
    )
    session.add(user)
    await session.flush()
    return user


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

    Plain (unlocked) read -- use `get_refresh_token_by_hash_for_update`
    instead for any caller that's about to rotate/revoke based on what
    it reads, so a concurrent rotation of the same token can't race it.
    """
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    return result.scalar_one_or_none()


async def get_refresh_token_by_hash_for_update(
    session: AsyncSession, token_hash: str
) -> RefreshToken | None:
    """Same lookup as `get_refresh_token_by_hash`, but takes a row lock
    (`SELECT ... FOR UPDATE`) on the returned row -- same pattern as
    `kalekit.organization.repository.remove_member`'s org-row lock.

    `/auth/refresh` is check-then-write: it reads a token's
    revoked/replaced_by state and then, if unrevoked, rotates it. Two
    requests racing in with the *same* token (e.g. a network retry, or
    two BFF instances refreshing concurrently) could otherwise both
    read `revoked=False` before either commits its rotation, and both
    proceed to rotate -- producing two successor rows from one token
    instead of the intended single rotation (the grace-window cache
    only smooths over a *replay* of an already-rotated token; it does
    nothing to prevent this simultaneous double-rotation). Locking the
    row here serializes any concurrent refreshes of the same token on
    this lock, so the second request only proceeds once the first has
    committed -- at which point it sees `revoked=True` and takes the
    grace-window/reuse-detection path instead of racing a second
    rotation through.
    """
    result = await session.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .with_for_update()
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
