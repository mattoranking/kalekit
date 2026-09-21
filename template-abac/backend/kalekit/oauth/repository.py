import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from kalekit.auth.repository import find_user_by_email
from kalekit.models.oauth_account import OAuthAccount
from kalekit.models.user import User
from kalekit.organization.repository import add_member, create_organization


async def find_oauth_account(
    session: AsyncSession,
    platform: str,
    account_id: str,
) -> OAuthAccount | None:
    result = await session.execute(
        select(OAuthAccount)
        .where(
            OAuthAccount.platform == platform,
            OAuthAccount.account_id == account_id,
        )
        # The callers read .user; a lazy load there raises MissingGreenlet
        # on an async session.
        .options(selectinload(OAuthAccount.user))
    )
    return result.scalar_one_or_none()


async def find_or_create_oauth_user(
    session: AsyncSession,
    *,
    platform: str,
    account_id: str,
    account_email: str | None,
    display_name: str | None = None,
) -> User:
    """Link an OAuth identity to a User, creating one if needed.

    Resolution order:
    1. Existing OAuthAccount(platform, account_id) → return linked User
    2. Existing User with matching email → link new OAuthAccount to them
    3. No match → create new User (password_hash=None) + OAuthAccount

    `account_email` may be None for providers that don't expose an email
    by default (e.g. Twitter/X). Rather than fabricate an unverifiable
    "@oauth.local" address -- which breaks email verification/reset and
    silently squats a namespace -- the user is stored with email=NULL.
    A partial unique index on users.email allows any number of such
    users to coexist.

    The provider's own access and refresh tokens are deliberately not
    accepted or stored: OAuth is used for login only, and the identity is
    matched on (platform, account_id).
    """
    # 1. Already linked?
    existing = await find_oauth_account(session, platform, account_id)
    if existing:
        return existing.user

    # 2. Email match → account merging
    user: User | None = None
    if account_email:
        user = await find_user_by_email(session, account_email)

    # 3. Brand-new user — same as the password signup path, they need
    # their own organization to belong to.
    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=account_email,
            password_hash=None,
        )
        session.add(user)
        await session.flush()

        # The org name must never be derived from the email address (its
        # local part would leak to anyone later invited). Prefer the
        # OAuth profile's display name when the provider gave us one,
        # otherwise fall back to the same generic default as password
        # signup.
        org_name = f"{display_name}'s workspace" if display_name else "My workspace"
        organization = await create_organization(
            session, name=org_name, created_by=user.id
        )
        await add_member(session, organization_id=organization.id, user_id=user.id)

    # Link the OAuth account
    oauth_account = OAuthAccount(
        user_id=user.id,
        platform=platform,
        account_id=account_id,
        account_email=account_email,
    )
    session.add(oauth_account)
    await session.flush()
    return user
