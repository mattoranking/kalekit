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
    device_info: str | None = None,
    ip_address: str | None = None,
) -> RefreshToken:
    token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        device_info=device_info,
        ip_address=ip_address,
    )
    session.add(token)
    await session.flush()
    return token


async def get_refresh_token_by_hash(
    session: AsyncSession, token_hash: str
) -> RefreshToken | None:
    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,      # noqa: E712
        )
    )
    return result.scalar_one_or_none()


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
