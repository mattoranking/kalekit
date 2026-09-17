import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.config import Environment, settings
from kalekit.models.organization import MemberRole, OrganizationMember
from kalekit.models.organization_invitation import OrganizationInvitation
from kalekit.organization.repository import create_invitation
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)


@pytest.mark.asyncio(loop_scope="session")
async def test_inviting_unknown_and_known_emails_return_identical_responses(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """The whole point of #24/#31: an org member can no longer tell,
    from the invite response, whether an email belongs to a registered
    user."""
    await register("alice@example.com")
    await register("bob@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    known = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "bob@example.com", "role": "member"},
        headers=auth_header(token_alice),
    )
    unknown = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "nobody@example.com", "role": "member"},
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
        json={"email": "bob@example.com", "role": "member"},
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
    alice_response = await register("alice@example.com")
    await register("bob@example.com")
    await register("mallory@example.com")
    token_mallory = await login("mallory@example.com")
    org_a = await org_id_for("alice@example.com")
    alice_id = uuid.UUID(alice_response.json()["id"])

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
        role=MemberRole.member,
        token_hash=hash_invitation_token(raw_token),
        invited_by=alice_id,
        expires_at=invitation_token_expiry(),
    )

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
async def test_accepting_an_expired_invitation_is_rejected(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    from datetime import datetime, timedelta, timezone

    alice_response = await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    alice_id = uuid.UUID(alice_response.json()["id"])

    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org_a),
        email="bob@example.com",
        role=MemberRole.member,
        token_hash=hash_invitation_token(raw_token),
        invited_by=alice_id,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    response = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_bob),
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_accepting_is_single_use(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    alice_response = await register("alice@example.com")
    await register("bob@example.com")
    token_bob = await login("bob@example.com")
    org_a = await org_id_for("alice@example.com")
    alice_id = uuid.UUID(alice_response.json()["id"])

    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org_a),
        email="bob@example.com",
        role=MemberRole.member,
        token_hash=hash_invitation_token(raw_token),
        invited_by=alice_id,
        expires_at=invitation_token_expiry(),
    )

    first = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_bob),
    )
    assert first.status_code == 201

    replay = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_bob),
    )
    assert replay.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_inviting_with_no_email_provider_configured_fails_the_request(
    client: AsyncClient,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`get_email_sender` raises outside dev/test when no real provider
    is configured (see `utils/email.py`). That must surface as a
    request-time failure of the invite endpoint itself, not get
    swallowed inside the `BackgroundTasks` callback that sends the
    email -- which runs after the 202 response is already on the wire,
    where a raised exception would only reach server logs while the
    caller is told "invitation sent" for an email that never goes out.
    """
    monkeypatch.setattr(settings, "ENV", Environment.production)

    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    with pytest.raises(RuntimeError):
        await client.post(
            f"/v1/organizations/{org_a}/invitations",
            json={"email": "bob@example.com", "role": "member"},
            headers=auth_header(token_alice),
        )

    # No invitation row was created either -- the failure happened
    # before `create_invitation`, not after a half-completed invite.
    result = await session.execute(
        select(func.count()).select_from(OrganizationInvitation)
    )
    assert result.scalar_one() == 0
