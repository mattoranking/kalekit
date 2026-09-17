"""Coverage for the per-org/per-inviter invitation rate limit (issue #24
/ RBAC #18): without it, a compromised or careless account could blast
invitations at arbitrary emails all day."""

import pytest

from kalekit.config import settings


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
