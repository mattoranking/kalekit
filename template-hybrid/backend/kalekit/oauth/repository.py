import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from kalekit.auth.repository import find_user_by_email
from kalekit.models.oauth_account import OAuthAccount
from kalekit.models.organization import MemberRole
from kalekit.models.user import User
from kalekit.organization.repository import add_member, create_organization


class OAuthAccountLinkingError(Exception):
    """Raised when an OAuth sign-in matches an existing user by email
    but linking would be unsafe (see find_or_create_oauth_user).

    A plain Exception, not an HTTPException: this is a repository module
    and shouldn't know about HTTP. The endpoint layer (oauth/endpoints.py)
    translates it to a 409.
    """


async def find_oauth_account(
    session: AsyncSession,
    platform: str,
    account_id: str,
) -> OAuthAccount | None:
    result = await session.execute(
        select(OAuthAccount)
        # Eager-load: find_or_create_oauth_user returns account.user, and a
        # lazy load there raises MissingGreenlet under the async session.
        .options(selectinload(OAuthAccount.user))
        .where(
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
    display_name: str | None = None,
    provider_email_verified: bool = False,
) -> User:
    """Link an OAuth identity to a User, creating one if needed.

    Resolution order:
    1. Existing OAuthAccount(platform, account_id) → return linked User
    2. Existing User with matching email → link new OAuthAccount to them,
       but ONLY if both sides have a verified email (see below)
    3. No match → create new User (password_hash=None) + OAuthAccount

    `account_email` may be None for providers that don't expose an email
    by default (e.g. Twitter/X). Rather than fabricate an unverifiable
    "@oauth.local" address -- which breaks email verification/reset and
    silently squats a namespace -- the user is stored with email=NULL.
    A partial unique index on users.email allows any number of such
    users to coexist.

    Why the verified-email gate on step 2: without it, an attacker can
    pre-hijack an account by registering victim@example.com with a
    password they control *before* the real owner signs up. When the
    real owner later signs in with Google/GitHub using that address,
    step 2 would silently link the attacker's existing account to the
    owner's OAuth identity, and both parties could log into it. Requiring
    `provider_email_verified` (the IdP vouches for the address) AND
    `user.email_verified` (the local account holder proved they control
    the mailbox, via /auth/verify-email) closes that hole.

    With `account_email` None there is nothing to match on, so step 2 is
    skipped and a separate, unverified user is created.
    """
    # 1. Already linked?
    existing = await find_oauth_account(session, platform, account_id)
    if existing:
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

    # 3. Brand-new user — same as the password signup path, they need
    # their own organization to belong to.
    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=account_email,
            password_hash=None,
            # Trust the IdP's own verification signal. A provider that
            # can't report an email or its verification status (e.g.
            # Twitter) yields an unverified account, like a fresh
            # password sign-up.
            email_verified=bool(account_email and provider_email_verified),
        )
        session.add(user)
        await session.flush()

        # The org name must never be derived from the email address (its
        # local part would leak to anyone later invited). Prefer the
        # OAuth profile's display name when the provider gave us one,
        # otherwise fall back to the same generic default as password
        # signup.
        org_name = f"{display_name}'s workspace" if display_name else "My workspace"
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
