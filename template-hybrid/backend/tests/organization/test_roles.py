import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_invite_at_any_role(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("owner@example.com")
    await register("viewer@example.com")
    token_owner = await login("owner@example.com")
    org = await org_id_for("owner@example.com")

    response = await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "viewer@example.com", "role": "viewer"},
        headers=auth_header(token_owner),
    )

    assert response.status_code == 201
    assert response.json()["role"] == "viewer"


@pytest.mark.asyncio(loop_scope="session")
async def test_viewer_cannot_invite(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    """Inviting needs admin+ -- a viewer, even though they're a real
    member of the org, is refused."""
    await register("owner@example.com")
    await register("viewer@example.com")
    await register("intruder@example.com")
    token_owner = await login("owner@example.com")
    token_viewer = await login("viewer@example.com")
    org = await org_id_for("owner@example.com")

    await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "viewer@example.com", "role": "viewer"},
        headers=auth_header(token_owner),
    )

    response = await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "intruder@example.com", "role": "member"},
        headers=auth_header(token_viewer),
    )

    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_invite(
    client: AsyncClient, register, login, auth_header, org_id_for
) -> None:
    await register("owner@example.com")
    await register("admin@example.com")
    await register("newperson@example.com")
    token_owner = await login("owner@example.com")
    token_admin = await login("admin@example.com")
    org = await org_id_for("owner@example.com")

    await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "admin@example.com", "role": "admin"},
        headers=auth_header(token_owner),
    )

    response = await client.post(
        f"/v1/organizations/{org}/members",
        json={"email": "newperson@example.com", "role": "member"},
        headers=auth_header(token_admin),
    )

    assert response.status_code == 201
