"""Coverage for the per-org/per-inviter invitation rate limit (issue #24
/ RBAC #18): without it, a compromised or careless account could blast
invitations at arbitrary emails all day."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.config import settings
from kalekit.organization.repository import add_member, create_organization


@pytest.mark.asyncio(loop_scope="session")
async def test_invitations_are_rate_limited_per_org(
    client, register, login, auth_header, org_id_for, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "INVITATION_RATE_LIMIT_PER_ORG", 2)
    monkeypatch.setattr(settings, "INVITATION_RATE_LIMIT_PER_INVITER", 1000)

    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    for i in range(2):
        response = await client.post(
            f"/v1/organizations/{org_a}/invitations",
            json={"email": f"invitee-{i}@example.com"},
            headers=auth_header(token_alice),
        )
        assert response.status_code == 202

    third = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "invitee-2@example.com"},
        headers=auth_header(token_alice),
    )
    assert third.status_code == 429


@pytest.mark.asyncio(loop_scope="session")
async def test_invitations_are_rate_limited_per_inviter(
    client, register, login, auth_header, org_id_for, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-org limit alone wouldn't catch one bad account spread
    across many orgs it created -- this is the per-user half of the
    same guard."""
    monkeypatch.setattr(settings, "INVITATION_RATE_LIMIT_PER_ORG", 1000)
    monkeypatch.setattr(settings, "INVITATION_RATE_LIMIT_PER_INVITER", 1)

    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    first = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "invitee-0@example.com"},
        headers=auth_header(token_alice),
    )
    assert first.status_code == 202

    second = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "invitee-1@example.com"},
        headers=auth_header(token_alice),
    )
    assert second.status_code == 429


@pytest.mark.asyncio(loop_scope="session")
async def test_an_org_exceeded_request_does_not_burn_the_inviters_own_quota(
    client,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request rejected for exceeding the *org*-wide limit must not
    also cost the inviter a unit of their own personal quota -- that
    inviter did nothing wrong, and their org being saturated shouldn't
    exhaust an unrelated counter of theirs (e.g. one that also covers
    invites they send from a different org they created).

    org_a's limit is set to 1 and alice's personal limit to 2. Two
    invites into org_a (the second rejected for exceeding org_a's
    limit) should only ever cost alice one unit of her own quota, not
    two -- leaving room for exactly one more successful invite from a
    second org she also created, org_b.
    """
    monkeypatch.setattr(settings, "INVITATION_RATE_LIMIT_PER_ORG", 1)
    monkeypatch.setattr(settings, "INVITATION_RATE_LIMIT_PER_INVITER", 2)

    alice_register = await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")
    alice_id = uuid.UUID(alice_register.json()["id"])

    org_b = await create_organization(session, name="Second Org", created_by=alice_id)
    await add_member(session, organization_id=org_b.id, user_id=alice_id)

    first = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "invitee-0@example.com"},
        headers=auth_header(token_alice),
    )
    assert first.status_code == 202  # org_a: 1/1, alice: 1/2

    second = await client.post(
        f"/v1/organizations/{org_a}/invitations",
        json={"email": "invitee-1@example.com"},
        headers=auth_header(token_alice),
    )
    assert second.status_code == 429  # org_a exceeded -- alice's quota untouched

    third = await client.post(
        f"/v1/organizations/{org_b.id}/invitations",
        json={"email": "invitee-2@example.com"},
        headers=auth_header(token_alice),
    )
    # Proves alice's quota is still 1/2, not 2/2: if the org-exceeded
    # request above had incorrectly also burned it, this would be her
    # third hit against a limit of 2 and get rejected instead.
    assert third.status_code == 202  # org_b: 1/1, alice: 2/2


@pytest.mark.asyncio(loop_scope="session")
async def test_invitations_fail_open_when_redis_is_down(
    client, register, login, auth_header, org_id_for, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rate limiting is an abuse control, not an authorization gate: a
    Redis outage must let the invitation through (#106), not surface as
    a 500 and not refuse every invitation."""
    import redis.exceptions

    class _DeadRedis:
        def __getattr__(self, name: str):
            async def _fail(*args: object, **kwargs: object) -> None:
                raise redis.exceptions.ConnectionError("simulated redis outage")

            return _fail

    async def _dead_get_redis() -> _DeadRedis:
        return _DeadRedis()

    monkeypatch.setattr("kalekit.organization.endpoints.get_redis", _dead_get_redis)
    monkeypatch.setattr(settings, "INVITATION_RATE_LIMIT_PER_ORG", 1)

    await register("alice@example.com")
    token_alice = await login("alice@example.com")
    org_a = await org_id_for("alice@example.com")

    # Past the (tiny) org limit, to show the limiter is not consulted
    # at all rather than silently counting somewhere.
    for i in range(2):
        response = await client.post(
            f"/v1/organizations/{org_a}/invitations",
            json={"email": f"invitee-{i}@example.com"},
            headers=auth_header(token_alice),
        )
        assert response.status_code == 202
