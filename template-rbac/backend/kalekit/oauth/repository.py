import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.auth.seed import assign_role, ensure_default_roles
from kalekit.models.oauth_account import OAuthAccount
from kalekit.models.user import User


class OAuthAccountLinkingError(Exception):
    """Raised when an OAuth sign-in matches an existing user by email
    but linking would be unsafe (see find_or_create_oauth_user).

    Deliberately a plain Exception, not an HTTPException -- this is a
    repository module and shouldn't know about HTTP. The endpoint
    layer (oauth/endpoints.py) translates it to a 409.
    """


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
    provider_email_verified: bool = False,
) -> User:
    """Link an OAuth identity to a User, creating one if needed.

    Resolution order:
    1. Existing OAuthAccount(platform, account_id) → return linked User
    2. Existing User with matching email → link new OAuthAccount to them,
       but ONLY if both sides have a verified email (see below)
    3. No match → create new User (password_hash=None) + OAuthAccount

    Why the verified-email gate on step 2: without it, an attacker can
    pre-hijack an account by registering victim@example.com with a
    password they control *before* the real owner ever signs up. When
    the real owner later signs in with Google/GitHub using that
    address, step 2 would silently link the attacker's existing
    account to the real owner's OAuth identity -- now both parties can
    log into the same account. Requiring `provider_email_verified`
    (the IdP itself vouches the address) AND `user.email_verified`
    (the local account holder proved they control the mailbox, via
    /auth/verify-email) closes that: an attacker's unverified
    password-only account can never be silently claimed by someone
    else's OAuth sign-in.
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

    # 2. Email match → account merging, gated on verification both ways
    user: User | None = None
    if account_email:
        candidate = await find_user_by_email(session, account_email)
        if candidate is not None:
            if not provider_email_verified or not candidate.email_verified:
                raise OAuthAccountLinkingError(
                    "An account with this email already exists and its "
                    "ownership can't be verified. Log in with your "
                    "password and verify your email, or use a different "
                    "email with this provider."
                )
            user = candidate

    # 3. Brand-new user
    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=account_email or f"{platform}_{account_id}@oauth.local",
            password_hash=None,
            # Trust the IdP's own verification signal. A provider that
            # can't report email or its verification status (e.g.
            # Twitter, or `account_email` missing) yields an unverified
            # local account, same as a fresh password sign-up.
            email_verified=bool(account_email and provider_email_verified),
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
