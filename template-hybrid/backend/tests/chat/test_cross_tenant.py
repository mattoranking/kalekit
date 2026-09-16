import pytest
from httpx import AsyncClient

from tests.conftest import TwoTenants


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_list_messages(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    """404, not 403 -- to a non-member, org A's chat doesn't exist
    rather than existing-but-forbidden."""
    response = await client.get(
        f"/v1/organizations/{two_tenants.org_a}/chat/",
        headers=auth_header(two_tenants.token_b),
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_post_message(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    """POST is org-scoped too -- a non-member can't write into another
    org's chat, and no message is created as a side effect of trying."""
    response = await client.post(
        f"/v1/organizations/{two_tenants.org_a}/chat/",
        json={"content": "should not land"},
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404

    response = await client.get(
        f"/v1/organizations/{two_tenants.org_a}/chat/",
        headers=auth_header(two_tenants.token_a),
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


@pytest.mark.asyncio(loop_scope="session")
async def test_non_member_cannot_delete_message(
    client: AsyncClient, auth_header, two_tenants: TwoTenants
) -> None:
    """A non-member hitting org A's message-delete URL gets 404 --
    `get_message()` is tenant-scoped, so the message doesn't resolve at
    all for a caller from org B, regardless of authorship or role."""
    post_response = await client.post(
        f"/v1/organizations/{two_tenants.org_a}/chat/",
        json={"content": "owned by org a"},
        headers=auth_header(two_tenants.token_a),
    )
    assert post_response.status_code == 201
    message_id = post_response.json()["id"]

    response = await client.delete(
        f"/v1/organizations/{two_tenants.org_a}/chat/{message_id}",
        headers=auth_header(two_tenants.token_b),
    )
    assert response.status_code == 404

    response = await client.get(
        f"/v1/organizations/{two_tenants.org_a}/chat/",
        headers=auth_header(two_tenants.token_a),
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1
