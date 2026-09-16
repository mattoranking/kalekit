import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.oauth.repository import find_or_create_oauth_user


@pytest.mark.asyncio(loop_scope="session")
async def test_new_oauth_user_without_email_gets_null_email(
    session: AsyncSession,
) -> None:
    """Providers that don't expose an email (e.g. Twitter/X) must not get a
    fabricated '@oauth.local' address -- it's unverifiable and breaks
    email-based flows like reset/verification."""
    user = await find_or_create_oauth_user(
        session,
        platform="twitter",
        account_id="12345",
        account_email=None,
        access_token="token",
    )

    assert user.email is None


@pytest.mark.asyncio(loop_scope="session")
async def test_two_emailless_oauth_users_can_coexist(
    session: AsyncSession,
) -> None:
    """Multiple NULL emails must not collide -- the uniqueness constraint
    on users.email only applies to non-NULL values."""
    user_a = await find_or_create_oauth_user(
        session,
        platform="twitter",
        account_id="aaa",
        account_email=None,
        access_token="token",
    )
    user_b = await find_or_create_oauth_user(
        session,
        platform="twitter",
        account_id="bbb",
        account_email=None,
        access_token="token",
    )

    assert user_a.id != user_b.id
    assert user_a.email is None
    assert user_b.email is None


@pytest.mark.asyncio(loop_scope="session")
async def test_new_oauth_user_default_organization_name_has_no_email(
    session: AsyncSession,
) -> None:
    """The default org name must never be derived from the email address."""
    user = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="99",
        account_email="carol@example.com",
        access_token="token",
    )
    await session.refresh(user, attribute_names=["memberships"])

    assert len(user.memberships) == 1
    org_name = user.memberships[0].organization.name
    assert org_name == "My workspace"
    assert "carol" not in org_name.lower()


@pytest.mark.asyncio(loop_scope="session")
async def test_new_oauth_user_organization_uses_display_name_when_available(
    session: AsyncSession,
) -> None:
    """When the provider profile has a display name, use it to name the
    default organization instead of the generic fallback."""
    user = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="100",
        account_email="dave@example.com",
        access_token="token",
        display_name="Dave Smith",
    )
    await session.refresh(user, attribute_names=["memberships"])

    assert user.memberships[0].organization.name == "Dave Smith's workspace"


@pytest.mark.asyncio(loop_scope="session")
async def test_new_oauth_user_becomes_owner_of_default_organization(
    session: AsyncSession,
) -> None:
    """Hybrid's org creator is always granted the owner role, same as the
    password-signup path."""
    user = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="101",
        account_email="erin@example.com",
        access_token="token",
    )
    await session.refresh(user, attribute_names=["memberships"])

    assert user.memberships[0].role.value == "owner"
