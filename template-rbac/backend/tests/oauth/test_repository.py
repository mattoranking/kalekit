import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.oauth.repository import find_or_create_oauth_user


@pytest.mark.asyncio(loop_scope="session")
async def test_first_oauth_user_becomes_visitor_not_admin(
    session: AsyncSession,
) -> None:
    """Same rule as password /auth/register -- a user whose only signup
    path is OAuth must not end up with zero roles, but also must not be
    auto-promoted to admin just for being first. Admin is only granted via
    `python -m kalekit.cli create-admin`."""
    user = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="12345",
        account_email="oauth-first@example.com",
        access_token="provider-token",
    )

    roles = [ur.role.name for ur in user.roles]
    assert roles == ["visitor"]


@pytest.mark.asyncio(loop_scope="session")
async def test_second_oauth_user_becomes_visitor(session: AsyncSession) -> None:
    await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="11111",
        account_email="first@example.com",
        access_token="token-1",
    )

    user = await find_or_create_oauth_user(
        session,
        platform="google",
        account_id="22222",
        account_email="oauth-second@example.com",
        access_token="token-2",
    )

    roles = [ur.role.name for ur in user.roles]
    assert roles == ["visitor"]


@pytest.mark.asyncio(loop_scope="session")
async def test_relinking_an_existing_oauth_account_does_not_reassign_a_role(
    session: AsyncSession,
) -> None:
    """A returning OAuth user hits branch 1 (already linked) -- their
    role shouldn't change just because they signed in again."""
    first = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="33333",
        account_email="returning@example.com",
        access_token="token-a",
    )
    first_roles = [ur.role.name for ur in first.roles]

    again = await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="33333",
        account_email="returning@example.com",
        access_token="token-b",
    )
    again_roles = [ur.role.name for ur in again.roles]

    assert again.id == first.id
    assert again_roles == first_roles
