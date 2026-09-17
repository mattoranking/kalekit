import pytest
from httpx import AsyncClient

from kalekit.models.organization import MemberRole


@pytest.mark.asyncio(loop_scope="session")
async def test_viewer_can_read_but_not_post(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("owner@example.com")
    await register("viewer@example.com")
    token_viewer = await login("viewer@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_viewer, "viewer@example.com", role=MemberRole.viewer)

    response = await client.get(
        f"/v1/organizations/{org}/chat/", headers=auth_header(token_viewer)
    )
    assert response.status_code == 200

    response = await client.post(
        f"/v1/organizations/{org}/chat/",
        json={"content": "hi"},
        headers=auth_header(token_viewer),
    )
    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_member_can_post_and_delete_own_message(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("owner@example.com")
    await register("member@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_member, "member@example.com", role=MemberRole.member)

    response = await client.post(
        f"/v1/organizations/{org}/chat/",
        json={"content": "hi from member"},
        headers=auth_header(token_member),
    )
    assert response.status_code == 201
    message_id = response.json()["id"]

    # Authors may delete their own message even without `chat:delete`.
    response = await client.delete(
        f"/v1/organizations/{org}/chat/{message_id}", headers=auth_header(token_member)
    )
    assert response.status_code == 204


@pytest.mark.asyncio(loop_scope="session")
async def test_member_cannot_delete_others_message(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("owner@example.com")
    await register("member-one@example.com")
    await register("member-two@example.com")
    token_member_one = await login("member-one@example.com")
    token_member_two = await login("member-two@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(
        org, token_member_one, "member-one@example.com", role=MemberRole.member
    )
    await add_member(
        org, token_member_two, "member-two@example.com", role=MemberRole.member
    )

    response = await client.post(
        f"/v1/organizations/{org}/chat/",
        json={"content": "hi from member one"},
        headers=auth_header(token_member_one),
    )
    assert response.status_code == 201
    message_id = response.json()["id"]

    response = await client.delete(
        f"/v1/organizations/{org}/chat/{message_id}",
        headers=auth_header(token_member_two),
    )
    assert response.status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_can_delete_anyones_message(
    client: AsyncClient, register, login, auth_header, org_id_for, add_member
) -> None:
    await register("owner@example.com")
    await register("member@example.com")
    token_owner = await login("owner@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")
    await add_member(org, token_member, "member@example.com", role=MemberRole.member)

    response = await client.post(
        f"/v1/organizations/{org}/chat/",
        json={"content": "hi from member"},
        headers=auth_header(token_member),
    )
    message_id = response.json()["id"]

    response = await client.delete(
        f"/v1/organizations/{org}/chat/{message_id}", headers=auth_header(token_owner)
    )
    assert response.status_code == 204
