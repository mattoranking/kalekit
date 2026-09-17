import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.service import hash_password
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.user import User


async def find_user_by_email(session: AsyncSession, email: str | None) -> User | None:
    if email is None:
        # SQLAlchemy rewrites `User.email == None` to `IS NULL`, which
        # WOULD match an arbitrary NULL-email user -- guard explicitly
        # so a caller never accidentally looks up "the user with no
        # email" and gets back someone else's account.
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
    """End every session for this user (every refresh token family).
    Used by /auth/logout-all -- a plain /auth/logout revokes only the
    presented session's family (see revoke_refresh_token_family)."""
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
