import uuid

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select

from kalekit.auth.repository import find_user_by_email
from kalekit.models.role import Permission, Role, RolePermission, UserRole
from kalekit.user.service import ensure_not_last_active_admin


async def _user_id(client: AsyncClient, login, auth_header, email: str) -> str:
    token = await login(email)
    response = await client.get("/v1/auth/me", headers=auth_header(token))
    assert response.status_code == 200, response.text
    return response.json()["id"]


@pytest_asyncio.fixture(loop_scope="session")
async def admin(register, promote_to_admin, login, auth_header, client):
    """An admin user: (id, admin-client token)."""
    await register("admin@example.com")
    await promote_to_admin("admin@example.com")
    uid = await _user_id(client, login, auth_header, "admin@example.com")
    token = await login("admin@example.com", client_type="admin")
    return uid, token


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_gets_user(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")

    response = await client.get(f"/v1/users/{bob_id}", headers=auth_header(token))

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == bob_id
    assert body["email"] == "bob@example.com"
    assert body["is_active"] is True
    assert body["email_verified"] is False
    assert body["roles"] == ["visitor"]
    assert "created_at" in body
    assert "password_hash" not in body


@pytest.mark.asyncio(loop_scope="session")
async def test_get_unknown_user_is_404(client: AsyncClient, auth_header, admin) -> None:
    _, token = admin

    response = await client.get(f"/v1/users/{uuid.uuid4()}", headers=auth_header(token))

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("method", ["get", "patch"])
@pytest.mark.parametrize("client_type", ["web", "mobile"])
async def test_admin_role_on_wrong_client_gets_404(
    client: AsyncClient, login, auth_header, admin, method, client_type
) -> None:
    uid, _ = admin
    kwargs = {"json": {"is_active": False}} if method == "patch" else {}
    token = await login("admin@example.com", client_type=client_type)

    response = await client.request(
        method, f"/v1/users/{uid}", headers=auth_header(token), **kwargs
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("method", ["get", "patch"])
async def test_visitor_gets_404(
    client: AsyncClient, register, login, auth_header, admin, method
) -> None:
    uid, _ = admin
    await register("visitor@example.com")
    token = await login("visitor@example.com", client_type="admin")
    kwargs = {"json": {"is_active": False}} if method == "patch" else {}

    response = await client.request(
        method, f"/v1/users/{uid}", headers=auth_header(token), **kwargs
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_suspend_cuts_off_token_and_reactivate_does_not_revive_it(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, admin_token = admin
    await register("bob@example.com")
    bob_token = await login("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")

    response = await client.patch(
        f"/v1/users/{bob_id}",
        headers=auth_header(admin_token),
        json={"is_active": False},
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert (
        await client.get("/v1/auth/me", headers=auth_header(bob_token))
    ).status_code == 401

    response = await client.patch(
        f"/v1/users/{bob_id}",
        headers=auth_header(admin_token),
        json={"is_active": True},
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is True
    # The version bump made at suspension keeps the old token dead.
    assert (
        await client.get("/v1/auth/me", headers=auth_header(bob_token))
    ).status_code == 401
    # A fresh login works again.
    new_token = await login("bob@example.com")
    assert (
        await client.get("/v1/auth/me", headers=auth_header(new_token))
    ).status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_reactivation_does_not_bump_token_version(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, admin_token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")
    bob_token = await login("bob@example.com")

    response = await client.patch(
        f"/v1/users/{bob_id}",
        headers=auth_header(admin_token),
        json={"is_active": True},
    )

    assert response.status_code == 200
    assert (
        await client.get("/v1/auth/me", headers=auth_header(bob_token))
    ).status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_cannot_deactivate_self(
    client: AsyncClient, register, promote_to_admin, auth_header, admin
) -> None:
    uid, token = admin
    # A second admin exists, so only the self rule can refuse this.
    await register("admin2@example.com")
    await promote_to_admin("admin2@example.com")

    response = await client.patch(
        f"/v1/users/{uid}", headers=auth_header(token), json={"is_active": False}
    )

    assert response.status_code == 409
    assert "yourself" in response.json()["detail"]


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_deactivate_another_admin_when_one_remains(
    client: AsyncClient, register, login, promote_to_admin, auth_header, admin
) -> None:
    _, token = admin
    await register("admin2@example.com")
    await promote_to_admin("admin2@example.com")
    admin2_id = await _user_id(client, login, auth_header, "admin2@example.com")

    response = await client.patch(
        f"/v1/users/{admin2_id}",
        headers=auth_header(token),
        json={"is_active": False},
    )

    assert response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_endpoint_refuses_last_active_admin(
    client: AsyncClient,
    session,
    register,
    login,
    auth_header,
    admin,
) -> None:
    """A non-admin role holding users:write (here "support") can reach the
    route, so the last-admin rule is the only thing protecting the sole
    admin."""
    admin_id, _ = admin
    perm = (
        await session.execute(
            select(Permission).where(Permission.name == "users:write")
        )
    ).scalar_one()
    support = Role(id=uuid.uuid4(), name="support", description="support staff")
    session.add(support)
    await session.flush()
    session.add(RolePermission(role_id=support.id, permission_id=perm.id))
    await register("support@example.com")
    support_user = await find_user_by_email(session, "support@example.com")
    assert support_user is not None
    session.add(UserRole(user_id=support_user.id, role_id=support.id))
    await session.flush()
    await session.refresh(support_user)
    token = await login("support@example.com", client_type="admin")

    response = await client.patch(
        f"/v1/users/{admin_id}", headers=auth_header(token), json={"is_active": False}
    )

    assert response.status_code == 409
    assert "last" in response.json()["detail"]
    target = await find_user_by_email(session, "admin@example.com")
    assert target is not None and target.is_active is True


@pytest.mark.asyncio(loop_scope="session")
async def test_helper_refuses_only_when_target_is_last_active_admin(
    session, register, promote_to_admin
) -> None:
    await register("only@example.com")
    await promote_to_admin("only@example.com")
    only = await find_user_by_email(session, "only@example.com")
    assert only is not None

    with pytest.raises(HTTPException) as exc:
        await ensure_not_last_active_admin(session, only)
    assert exc.value.status_code == 409

    await register("second@example.com")
    await promote_to_admin("second@example.com")
    await ensure_not_last_active_admin(session, only)


@pytest.mark.asyncio(loop_scope="session")
async def test_helper_ignores_inactive_admins_and_non_admins(
    session, register, promote_to_admin
) -> None:
    await register("a@example.com")
    await promote_to_admin("a@example.com")
    await register("b@example.com")
    await promote_to_admin("b@example.com")
    await register("visitor@example.com")
    a = await find_user_by_email(session, "a@example.com")
    b = await find_user_by_email(session, "b@example.com")
    visitor = await find_user_by_email(session, "visitor@example.com")
    assert a is not None and b is not None and visitor is not None
    b.is_active = False
    await session.flush()

    with pytest.raises(HTTPException) as exc:
        await ensure_not_last_active_admin(session, a)
    assert exc.value.status_code == 409
    # A user who is not an admin is never "the last admin".
    await ensure_not_last_active_admin(session, visitor)


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "body",
    [
        {"email": "new@example.com"},
        {"is_active": False, "email": "new@example.com"},
        {"is_active": False, "roles": ["admin"]},
        {},
        {"is_active": None},
    ],
)
async def test_patch_rejects_other_fields(
    client: AsyncClient, register, login, auth_header, admin, body
) -> None:
    _, token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")

    response = await client.patch(
        f"/v1/users/{bob_id}", headers=auth_header(token), json=body
    )

    assert response.status_code == 422
    bob = await client.get(f"/v1/users/{bob_id}", headers=auth_header(token))
    assert bob.json()["email"] == "bob@example.com"
    assert bob.json()["is_active"] is True


@pytest.mark.asyncio(loop_scope="session")
async def test_patch_unknown_user_is_404(
    client: AsyncClient, auth_header, admin
) -> None:
    _, token = admin

    response = await client.patch(
        f"/v1/users/{uuid.uuid4()}",
        headers=auth_header(token),
        json={"is_active": False},
    )

    assert response.status_code == 404
