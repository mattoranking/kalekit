import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select

from kalekit.auth.repository import find_user_by_email
from kalekit.auth.scope import SCOPES_SUPPORTED, Scope
from kalekit.auth.seed import ensure_default_roles
from kalekit.models.role import Permission, Role, RolePermission, UserRole


async def _user_id(client: AsyncClient, login, auth_header, email: str) -> str:
    token = await login(email)
    response = await client.get("/v1/auth/me", headers=auth_header(token))
    assert response.status_code == 200, response.text
    return response.json()["id"]


async def _add_role(session, name: str, permissions: list[str]) -> Role:
    """A role that exists only in the database, not in roles.yaml."""
    role = Role(id=uuid.uuid4(), name=name, description=f"{name} (db only)")
    session.add(role)
    await session.flush()
    for permission_name in permissions:
        permission = (
            await session.execute(
                select(Permission).where(Permission.name == permission_name)
            )
        ).scalar_one()
        session.add(RolePermission(role_id=role.id, permission_id=permission.id))
    await session.flush()
    return role


@pytest_asyncio.fixture(loop_scope="session")
async def admin(register, promote_to_admin, login, auth_header, client):
    """An admin user: (id, admin-client token)."""
    await register("admin@example.com")
    await promote_to_admin("admin@example.com")
    uid = await _user_id(client, login, auth_header, "admin@example.com")
    token = await login("admin@example.com", client_type="admin")
    return uid, token


@pytest_asyncio.fixture(loop_scope="session")
async def support_token(session, register, login):
    """Token of a non-admin user whose only role holds roles:write and
    users:read, so the last-admin rule is the only guard in its way."""
    await register("support@example.com")
    role = await _add_role(session, "support", ["roles:write", "users:read"])
    user = await find_user_by_email(session, "support@example.com")
    assert user is not None
    session.add(UserRole(user_id=user.id, role_id=role.id))
    await session.flush()
    await session.refresh(user)
    return await login("support@example.com", client_type="admin")


def test_roles_scopes_are_supported() -> None:
    assert Scope.roles_read.value == "roles:read"
    assert Scope.roles_write.value == "roles:write"
    assert "roles:read" in SCOPES_SUPPORTED
    assert "roles:write" in SCOPES_SUPPORTED


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_role_is_granted_the_roles_scopes(session) -> None:
    _, admin_role = await ensure_default_roles(session)

    granted = (
        (
            await session.execute(
                select(Permission.name)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .where(RolePermission.role_id == admin_role.id)
            )
        )
        .scalars()
        .all()
    )

    assert {"roles:read", "roles:write"} <= set(granted)


@pytest.mark.asyncio(loop_scope="session")
async def test_list_roles_reads_the_database(
    client: AsyncClient, session, auth_header, admin
) -> None:
    _, token = admin
    await _add_role(session, "auditor", ["posts:read"])

    response = await client.get("/v1/roles", headers=auth_header(token))

    assert response.status_code == 200
    by_name = {r["name"]: r for r in response.json()["items"]}
    assert set(by_name) == {"visitor", "admin", "auditor"}
    assert by_name["auditor"]["description"] == "auditor (db only)"
    assert by_name["auditor"]["permissions"] == ["posts:read"]
    assert by_name["visitor"]["permissions"] == []
    assert {"roles:read", "roles:write", "users:read"} <= set(
        by_name["admin"]["permissions"]
    )


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("client_type", ["web", "mobile"])
async def test_list_roles_on_wrong_client_is_404(
    client: AsyncClient, login, auth_header, admin, client_type
) -> None:
    token = await login("admin@example.com", client_type=client_type)

    response = await client.get("/v1/roles", headers=auth_header(token))

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_list_roles_without_the_scope_is_404(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    await register("visitor@example.com")
    token = await login("visitor@example.com", client_type="admin")

    response = await client.get("/v1/roles", headers=auth_header(token))

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_users_read_alone_does_not_open_roles_read(
    client: AsyncClient, session, register, login, auth_header, admin
) -> None:
    await register("reader@example.com")
    role = await _add_role(session, "reader", ["users:read", "users:write"])
    user = await find_user_by_email(session, "reader@example.com")
    assert user is not None
    session.add(UserRole(user_id=user.id, role_id=role.id))
    await session.flush()
    await session.refresh(user)
    token = await login("reader@example.com", client_type="admin")

    assert (
        await client.get("/v1/users/", headers=auth_header(token))
    ).status_code == 200
    assert (
        await client.get("/v1/roles", headers=auth_header(token))
    ).status_code == 404
    assert (
        await client.put(
            f"/v1/users/{user.id}/roles",
            headers=auth_header(token),
            json={"roles": ["visitor"]},
        )
    ).status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_put_roles_replaces_the_set_and_cuts_off_old_token(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, admin_token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")
    old_token = await login("bob@example.com", client_type="admin")
    # A plain visitor can't use the back office yet.
    assert (
        await client.get("/v1/users/", headers=auth_header(old_token))
    ).status_code == 404

    response = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["visitor", "admin"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == bob_id
    assert sorted(body["roles"]) == ["admin", "visitor"]
    # The old token carries the old scopes and version: cut off at once.
    assert (
        await client.get("/v1/auth/me", headers=auth_header(old_token))
    ).status_code == 401
    # A fresh token has the new scopes.
    new_token = await login("bob@example.com", client_type="admin")
    assert (
        await client.get("/v1/users/", headers=auth_header(new_token))
    ).status_code == 200

    # Replace, not add: dropping admin leaves only visitor.
    response = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["visitor"]},
    )
    assert response.status_code == 200
    assert response.json()["roles"] == ["visitor"]
    shown = await client.get(f"/v1/users/{bob_id}", headers=auth_header(admin_token))
    assert shown.json()["roles"] == ["visitor"]


@pytest.mark.asyncio(loop_scope="session")
async def test_put_roles_with_an_empty_list_removes_every_role(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, admin_token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")

    response = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": []},
    )

    assert response.status_code == 200
    assert response.json()["roles"] == []


@pytest.mark.asyncio(loop_scope="session")
async def test_put_roles_duplicates_in_the_body_are_one_role(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, admin_token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")

    response = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["visitor", "visitor"]},
    )

    assert response.status_code == 200
    assert response.json()["roles"] == ["visitor"]


@pytest.mark.asyncio(loop_scope="session")
async def test_put_unchanged_roles_leaves_tokens_alone(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, admin_token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")
    bob_token = await login("bob@example.com")

    response = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 200
    assert (
        await client.get("/v1/auth/me", headers=auth_header(bob_token))
    ).status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_put_unknown_role_is_422_and_changes_nothing(
    client: AsyncClient, register, login, auth_header, admin
) -> None:
    _, admin_token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")
    bob_token = await login("bob@example.com")

    response = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["admin", "no-such-role"]},
    )

    assert response.status_code == 422
    assert "no-such-role" in response.text
    shown = await client.get(f"/v1/users/{bob_id}", headers=auth_header(admin_token))
    assert shown.json()["roles"] == ["visitor"]
    assert (
        await client.get("/v1/auth/me", headers=auth_header(bob_token))
    ).status_code == 200


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "body",
    [{}, {"roles": "admin"}, {"roles": [1]}, {"roles": ["visitor"], "x": 1}],
)
async def test_put_bad_body_is_422(
    client: AsyncClient, auth_header, admin, body
) -> None:
    uid, token = admin

    response = await client.put(
        f"/v1/users/{uid}/roles", headers=auth_header(token), json=body
    )

    assert response.status_code == 422


@pytest.mark.asyncio(loop_scope="session")
async def test_put_unknown_user_is_404(client: AsyncClient, auth_header, admin) -> None:
    _, token = admin

    response = await client.put(
        f"/v1/users/{uuid.uuid4()}/roles",
        headers=auth_header(token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_cannot_remove_their_own_admin_role(
    client: AsyncClient, register, promote_to_admin, auth_header, admin
) -> None:
    uid, token = admin
    # A second admin exists, so only the self rule can refuse this.
    await register("admin2@example.com")
    await promote_to_admin("admin2@example.com")

    response = await client.put(
        f"/v1/users/{uid}/roles",
        headers=auth_header(token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 409
    assert "your own admin role" in response.json()["detail"]
    shown = await client.get(f"/v1/users/{uid}", headers=auth_header(token))
    assert "admin" in shown.json()["roles"]


@pytest.mark.asyncio(loop_scope="session")
async def test_admin_can_remove_another_admins_role_when_one_remains(
    client: AsyncClient, register, login, promote_to_admin, auth_header, admin
) -> None:
    _, token = admin
    await register("admin2@example.com")
    await promote_to_admin("admin2@example.com")
    admin2_id = await _user_id(client, login, auth_header, "admin2@example.com")

    response = await client.put(
        f"/v1/users/{admin2_id}/roles",
        headers=auth_header(token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 200
    assert response.json()["roles"] == ["visitor"]


@pytest.mark.asyncio(loop_scope="session")
async def test_cannot_remove_the_role_from_the_last_active_admin(
    client: AsyncClient, auth_header, admin, support_token
) -> None:
    admin_id, _ = admin

    response = await client.put(
        f"/v1/users/{admin_id}/roles",
        headers=auth_header(support_token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 409
    assert "last" in response.json()["detail"]
    shown = await client.get(
        f"/v1/users/{admin_id}", headers=auth_header(support_token)
    )
    assert "admin" in shown.json()["roles"]


@pytest.mark.asyncio(loop_scope="session")
async def test_an_inactive_admin_does_not_count_for_the_last_admin_rule(
    client: AsyncClient, session, register, login, auth_header, admin, support_token
) -> None:
    admin_id, _ = admin
    await register("admin2@example.com")
    admin2 = await find_user_by_email(session, "admin2@example.com")
    assert admin2 is not None
    _, admin_role = await ensure_default_roles(session)
    session.add(UserRole(user_id=admin2.id, role_id=admin_role.id))
    admin2.is_active = False
    await session.flush()

    response = await client.put(
        f"/v1/users/{admin_id}/roles",
        headers=auth_header(support_token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 409


@pytest.mark.asyncio(loop_scope="session")
async def test_put_roles_does_not_touch_the_role_cache(
    client: AsyncClient, monkeypatch, register, login, auth_header, admin
) -> None:
    calls: list[str] = []

    async def _spy(role_name: str) -> None:
        calls.append(role_name)

    monkeypatch.setattr("kalekit.auth.permissions.invalidate_role_cache", _spy)
    _, admin_token = admin
    await register("bob@example.com")
    bob_id = await _user_id(client, login, auth_header, "bob@example.com")

    response = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["visitor", "admin"]},
    )

    assert response.status_code == 200
    assert calls == []


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("client_type", ["web", "mobile"])
async def test_put_roles_on_wrong_client_is_404(
    client: AsyncClient, login, auth_header, admin, client_type
) -> None:
    uid, _ = admin
    token = await login("admin@example.com", client_type=client_type)

    response = await client.put(
        f"/v1/users/{uid}/roles",
        headers=auth_header(token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("client_type", ["web", "admin"])
async def test_put_roles_malformed_json_from_non_admin_is_404(
    client: AsyncClient, register, login, auth_header, admin, client_type
) -> None:
    """The guard runs before the body is parsed, so broken JSON from a
    caller who is not allowed does not show that the route exists."""
    uid, _ = admin
    await register("visitor@example.com")
    token = await login("visitor@example.com", client_type=client_type)

    response = await client.put(
        f"/v1/users/{uid}/roles",
        headers={**auth_header(token), "Content-Type": "application/json"},
        content="{not json",
    )

    assert response.status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_put_roles_malformed_json_from_admin_is_422(
    client: AsyncClient, auth_header, admin
) -> None:
    uid, token = admin

    response = await client.put(
        f"/v1/users/{uid}/roles",
        headers={**auth_header(token), "Content-Type": "application/json"},
        content="{not json",
    )

    assert response.status_code == 422


@pytest.mark.asyncio(loop_scope="session")
async def test_put_roles_removes_a_duplicate_user_role_row(
    client: AsyncClient, session, register, auth_header, admin
) -> None:
    """user_roles has no unique (user, role) constraint, so a past race can
    leave two rows for one role. Removing the role must remove both."""
    _, admin_token = admin
    await register("bob@example.com")
    bob = await find_user_by_email(session, "bob@example.com")
    assert bob is not None
    _, admin_role = await ensure_default_roles(session)
    session.add(UserRole(user_id=bob.id, role_id=admin_role.id))
    session.add(UserRole(user_id=bob.id, role_id=admin_role.id))
    await session.flush()

    response = await client.put(
        f"/v1/users/{bob.id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["visitor"]},
    )

    assert response.status_code == 200
    assert response.json()["roles"] == ["visitor"]
    rows = (
        await session.execute(
            select(UserRole).where(
                UserRole.user_id == bob.id, UserRole.role_id == admin_role.id
            )
        )
    ).all()
    assert rows == []
