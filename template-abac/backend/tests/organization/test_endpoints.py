import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.organization import OrganizationMember
from kalekit.oauth.repository import find_or_create_oauth_user
from kalekit.organization.repository import add_member, create_invitation
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)
from tests.conftest import TwoTenants


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_list_and_add_members(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_alice)
    )
    assert response.status_code == 200
    assert len(response.json()["items"]) == 1

    await add_member(org_a, token_bob, "bob@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_alice)
    )
    assert len(response.json()["items"]) == 2


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_see_members(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """404, not 403 -- to a non-member, this organization's members list
    doesn't exist rather than existing-but-forbidden."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_bob)
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_listing_members_with_null_email_returns_200(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    """A member who signed up through a provider that doesn't expose an
    email (e.g. Twitter/X, see #28) has `User.email = None`. Listing
    members must serialize that member as `email: null` instead of
    raising a 500 from `MemberResponse` validation -- see #70."""
    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    oauth_user = await find_or_create_oauth_user(
        session,
        platform="twitter",
        account_id="no-email-user",
        account_email=None,
        access_token="token",
    )
    await add_member(
        session, organization_id=uuid.UUID(org_a), user_id=oauth_user.id
    )

    response = await client.get(
        f"/v1/organizations/{org_a}/members", headers=auth_header(token_alice)
    )

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 2
    member = next(item for item in items if item["user_id"] == str(oauth_user.id))
    assert member["email"] is None


@pytest.mark.asyncio(loop_scope="session")
async def test_inviting_unknown_and_known_emails_return_identical_responses(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """The whole point of #24: an org member can no longer tell, from the
    invite response, whether an email belongs to a registered user."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    known = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "bob@example.com"},
        headers=auth_header(token_alice),
    )
    unknown = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "nobody@example.com"},
        headers=auth_header(token_alice),
    )

    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()


@pytest.mark.asyncio(loop_scope="session")
async def test_inviting_creates_no_membership(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    """No membership exists until the invitee accepts -- sending the
    invitation alone must never add a row."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    response = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "bob@example.com"},
        headers=auth_header(token_alice),
    )
    assert response.status_code == 202

    result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(org_a))
    )
    assert result.scalar_one() == 1  # only alice, the owner


@pytest.mark.asyncio(loop_scope="session")
async def test_member_who_is_not_creator_cannot_invite(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    """Flat membership doesn't mean every member can grow the tenant --
    only the org's creator may invite (issue #24's policy decision)."""
    await register("alice@example.com")
    await register("bob@example.com")
    await register("carol@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    await add_member(org_a, token_bob, "bob@example.com")

    response = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "carol@example.com"},
        headers=auth_header(token_bob),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_accepting_requires_matching_authenticated_email(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    """The invitation's email is never trusted from anywhere but the
    authenticated caller -- someone else can't ride another person's
    invitation link into the org."""
    await register("alice@example.com")
    await register("bob@example.com")
    await register("mallory@example.com")
    token_mallory = await login("mallory@example.com")
    org_a = await org_id_for("alice@example.com")

    # The invite endpoint never returns the raw token (only its hash is
    # persisted, and the real token is only ever emailed to bob) -- so a
    # genuine invitation for bob is created directly here, exactly like
    # the invite endpoint would, so the test can hold the real token
    # Mallory has no legitimate way to obtain in production.
    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org_a),
        email="bob@example.com",
        token_hash=hash_invitation_token(raw_token),
        invited_by=None,
        expires_at=invitation_token_expiry(),
    )

    # Mallory has no way to obtain bob's raw token in production (it's
    # only ever emailed to bob) -- this asserts the identity check that
    # protects that boundary: even holding the real token, authenticating
    # as someone whose email doesn't match it is rejected.
    response = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_mallory),
    )
    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_accepting_an_invalid_token_is_rejected(
    client: AsyncClient, register, login, auth_header
) -> None:
    await register("bob@example.com")
    token_bob = await login("bob@example.com")

    response = await client.post(
        "/v1/invitations/accept",
        json={"token": "totally-made-up"},
        headers=auth_header(token_bob),
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_accepting_a_fresh_invite_while_already_a_member_returns_409(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
    add_member,
) -> None:
    """A second, independently-issued invitation for someone who is
    already a member is rejected (409), and never creates a duplicate
    membership row -- `add_member`'s own idempotency, surfaced through
    the accept endpoint."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")

    await add_member(org_a, token_bob, "bob@example.com")

    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org_a),
        email="bob@example.com",
        token_hash=hash_invitation_token(raw_token),
        invited_by=None,
        expires_at=invitation_token_expiry(),
    )
    response = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_bob),
    )
    assert response.status_code == 409

    result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(org_a))
    )
    assert result.scalar_one() == 2  # alice (owner) + bob, no duplicate

    # The 409 above must not have left the token usable: it was
    # genuinely consumed (`accepted_at` set), not silently left valid by
    # a rollback that undid `mark_invitation_accepted` along with the
    # error response. A second accept of the *same* token now sees an
    # already-accepted, no-longer-valid invitation -- 400, not another
    # 409 -- which is the only observable proof the mark stuck.
    replay = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_bob),
    )
    assert replay.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_invite(
    client: AsyncClient,
    session: AsyncSession,
    auth_header,
    two_tenants: TwoTenants,
) -> None:
    """A non-member can't invite anyone into another org's membership
    list either -- same 404 gate, and it never reaches `create_invitation`."""
    response = await client.post(
        f"/v1/organizations/{two_tenants.org_a}/invitations",
        json={"email": "tenant-b@example.com"},
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404

    result = await session.execute(
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == uuid.UUID(two_tenants.org_a))
    )
    assert result.scalar_one() == 1  # only the org's own owner
