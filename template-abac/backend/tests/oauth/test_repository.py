import pytest
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models import OAuthAccount
from kalekit.oauth.repository import find_or_create_oauth_user
from kalekit.organization.repository import list_user_organizations


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
    )
    user_b = await find_or_create_oauth_user(
        session,
        platform="twitter",
        account_id="bbb",
        account_email=None,
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
    )

    organizations = await list_user_organizations(session, user_id=user.id)
    assert len(organizations) == 1
    assert organizations[0].name == "My workspace"
    assert "carol" not in organizations[0].name.lower()


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
        display_name="Dave Smith",
    )

    organizations = await list_user_organizations(session, user_id=user.id)
    assert organizations[0].name == "Dave Smith's workspace"


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_login_stores_no_provider_token_and_matches_returning_user(
    session: AsyncSession,
) -> None:
    """OAuth is login-only (#116): the provider's tokens are never persisted,
    and a returning user is matched by (platform, account_id)."""
    first = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="returning-1",
        account_email="erin@example.com",
    )

    columns = {column.key for column in inspect(OAuthAccount).columns}
    assert not any("token" in column for column in columns)
    assert {"platform", "account_id", "account_email", "user_id"} <= columns

    # Same provider identity, different email: still the same user.
    again = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="returning-1",
        account_email="changed@example.com",
    )
    assert again.id == first.id

    accounts = (
        (
            await session.execute(
                select(OAuthAccount).where(OAuthAccount.account_id == "returning-1")
            )
        )
        .scalars()
        .all()
    )
    assert len(accounts) == 1
    assert accounts[0].user_id == first.id
    assert accounts[0].platform == "github"
