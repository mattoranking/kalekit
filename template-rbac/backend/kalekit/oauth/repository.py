import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.auth.seed import assign_role, ensure_default_roles
from kalekit.models.oauth_account import OAuthAccount
from kalekit.models.user import User


async def find_oauth_account(
    session: AsyncSession,
    platform: str,
    account_id: str,
) -> OAuthAccount | None:
    result = await session.execute(
        select(OAuthAccount).where(
            OAuthAccount.platform == platform,
            OAuthAccount.account_id == account_id,
        )
    )
    return result.scalar_one_or_none()


async def find_or_create_oauth_user(
    session: AsyncSession,
    *,
    platform: str,
    account_id: str,
    account_email: str | None,
    access_token: str,
    refresh_token: str | None = None,
) -> User:
    """Link an OAuth identity to a User, creating one if needed.

    Resolution order:
    1. Existing OAuthAccount(platform, account_id) → return linked User
    2. Existing User with matching email → link new OAuthAccount to them
    3. No match → create new User (password_hash=None) + OAuthAccount
    """
    # 1. Already linked?
    existing = await find_oauth_account(session, platform, account_id)
    if existing:
        # Update the stored tokens in case they were rotated
        existing.access_token = access_token
        if refresh_token:
            existing.refresh_token = refresh_token
        await session.flush()
        return existing.user

    # 2. Email match → account merging
    user: User | None = None
    if account_email:
        user = await find_user_by_email(session, account_email)

    # 3. Brand-new user
    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=account_email or f"{platform}_{account_id}@oauth.local",
            password_hash=None,
        )
        session.add(user)
        await session.flush()

        # Same role-assignment rule as password /auth/register -- without
        # this, a user whose only signup path was OAuth ends up with no
        # roles at all, and require_permission rejects them everywhere.
        visitor_role, admin_role = await ensure_default_roles(session)
        user_count = (await session.execute(select(func.count(User.id)))).scalar_one()
        assigned_role = admin_role if user_count == 1 else visitor_role
        await assign_role(session, user, assigned_role)

        # `user` was constructed in-memory, not loaded via a SELECT, so
        # selectin eager-loading never ran for it -- an unrefreshed
        # `.roles` access later would try to lazy-load outside an
        # active greenlet and crash. Refresh it now, once, here.
        await session.refresh(user, attribute_names=["roles"])

    # Link the OAuth account
    oauth_account = OAuthAccount(
        user_id=user.id,
        platform=platform,
        account_id=account_id,
        account_email=account_email,
        access_token=access_token,
        refresh_token=refresh_token,
    )
    session.add(oauth_account)
    await session.flush()
    return user
