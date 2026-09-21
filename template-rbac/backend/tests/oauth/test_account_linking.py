"""Covers the account-pre-hijack attack from issue #7:

  1. Attacker registers victim@example.com with a password they control.
  2. The real owner later signs in with an OAuth provider using that
     address.
  3. Without the verified-email gate, step 2 silently links the
     attacker's existing account to the OAuth identity -- both parties
     can now access it.

find_or_create_oauth_user must refuse to link unless the provider
vouches the email is verified AND the local account's email is
verified too.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import create_user, find_user_by_email
from kalekit.oauth.repository import (
    OAuthAccountLinkingError,
    find_or_create_oauth_user,
)


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_does_not_link_to_an_unverified_local_account(
    session: AsyncSession,
) -> None:
    """The attack scenario: attacker pre-registers the victim's email
    with a password-only, unverified account."""
    await create_user(
        session, "victim@example.com", "attacker-controlled-password"
    )

    with pytest.raises(OAuthAccountLinkingError):
        await find_or_create_oauth_user(
            session,
            platform="google",
            account_id="victim-google-id",
            account_email="victim@example.com",
            provider_email_verified=True,
        )

    # And no OAuth account got attached to the attacker's user either.
    user = await find_user_by_email(session, "victim@example.com")
    assert user is not None
    assert user.oauth_accounts == []


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_does_not_link_when_provider_email_is_unverified(
    session: AsyncSession,
) -> None:
    """Even a verified local account must not be linked if the IdP
    itself won't vouch for the email (e.g. an unconfirmed address at
    the provider)."""
    await create_user(
        session, "verified-owner@example.com", "password123", email_verified=True
    )

    with pytest.raises(OAuthAccountLinkingError):
        await find_or_create_oauth_user(
            session,
            platform="google",
            account_id="some-google-id",
            account_email="verified-owner@example.com",
            provider_email_verified=False,
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_links_when_both_sides_are_verified(
    session: AsyncSession,
) -> None:
    """The legitimate case: the local account is verified and the
    provider vouches for the email too -- linking should succeed."""
    local_user = await create_user(
        session, "legit@example.com", "password123", email_verified=True
    )

    linked_user = await find_or_create_oauth_user(
        session,
        platform="google",
        account_id="legit-google-id",
        account_email="legit@example.com",
        provider_email_verified=True,
    )

    assert linked_user.id == local_user.id
    # `linked_user` is the same in-memory object as `local_user`, loaded
    # before the OAuthAccount existed -- selectin eager-loading doesn't
    # retroactively refresh it, so pull the relationship explicitly.
    await session.refresh(linked_user, attribute_names=["oauth_accounts"])
    assert len(linked_user.oauth_accounts) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_new_oauth_user_is_verified_when_provider_says_so(
    session: AsyncSession,
) -> None:
    user = await find_or_create_oauth_user(
        session,
        platform="google",
        account_id="brand-new-verified",
        account_email="brand-new-verified@example.com",
        provider_email_verified=True,
    )

    assert user.email_verified is True


@pytest.mark.asyncio(loop_scope="session")
async def test_new_oauth_user_is_unverified_when_provider_does_not_confirm(
    session: AsyncSession,
) -> None:
    """No existing user to accidentally hijack here, so this doesn't
    need to be refused -- but it also shouldn't be trusted as verified
    without the provider's say-so (e.g. Twitter, which never returns
    an email)."""
    user = await find_or_create_oauth_user(
        session,
        platform="twitter",
        account_id="brand-new-twitter",
        account_email=None,
        provider_email_verified=False,
    )

    assert user.email_verified is False
