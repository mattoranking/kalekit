"""Tests for reading default roles/permissions from the checked-in
`auth/roles.yaml` file (issue #2), as opposed to hardcoded Python.
"""

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.scope import SCOPES_SUPPORTED
from kalekit.auth.seed import (
    ADMIN_ROLE,
    VISITOR_ROLE,
    RoleSeedFile,
    _load_role_definitions,
    ensure_default_roles,
)
from kalekit.models.role import Role, RolePermission


def test_shipped_roles_file_defines_visitor_and_admin() -> None:
    """The real, checked-in `roles.yaml` must define both roles every
    other part of the app (cli.py, oauth/repository.py, endpoints.py)
    assumes exist."""
    definitions = _load_role_definitions()

    assert set(definitions) >= {VISITOR_ROLE, ADMIN_ROLE}
    assert definitions[VISITOR_ROLE].permissions == []
    assert definitions[ADMIN_ROLE].permissions == ["*"]


def test_role_seed_file_rejects_missing_required_role(
    tmp_path: Path, monkeypatch
) -> None:
    """A seed file missing 'visitor' or 'admin' should fail loudly at
    load time rather than surface as a confusing KeyError deep inside
    `ensure_default_roles`."""
    import kalekit.auth.seed as seed_module

    bad_file = tmp_path / "roles.yaml"
    bad_file.write_text(
        textwrap.dedent(
            """\
            roles:
              admin:
                description: "Full access"
                permissions: ["*"]
            """
        )
    )
    monkeypatch.setattr(seed_module, "ROLE_SEED_FILE", bad_file)

    with pytest.raises(ValueError, match="visitor"):
        seed_module._load_role_definitions()


def test_role_seed_file_rejects_malformed_shape() -> None:
    """Permissions must be a list of strings -- a malformed file should
    fail schema validation, not silently seed nothing."""
    with pytest.raises(ValidationError):
        RoleSeedFile.model_validate({"roles": {"visitor": {"description": "x"}}})


def test_role_seed_file_rejects_unknown_permission() -> None:
    """A typo'd scope string (e.g. 'psots:write' instead of
    'posts:write') must fail loudly at load time, not silently create
    an unusable `Permission` row at the DB layer."""
    with pytest.raises(ValidationError, match="psots:write"):
        RoleSeedFile.model_validate(
            {
                "roles": {
                    "visitor": {"description": "x", "permissions": []},
                    "admin": {"description": "y", "permissions": ["*"]},
                    "editor": {
                        "description": "z",
                        "permissions": ["psots:write"],
                    },
                }
            }
        )


def test_role_seed_file_rejects_duplicate_permission() -> None:
    """A role listing the same (valid) permission twice must fail at
    load time -- otherwise `_ensure_role_permissions` would try to
    insert two identical `RolePermission` rows in the same
    `begin_nested()`, hit the primary key, and silently roll back every
    other permission grant in that call."""
    with pytest.raises(ValidationError, match="posts:write"):
        RoleSeedFile.model_validate(
            {
                "roles": {
                    "visitor": {"description": "x", "permissions": []},
                    "admin": {"description": "y", "permissions": ["*"]},
                    "editor": {
                        "description": "z",
                        "permissions": ["posts:write", "posts:write"],
                    },
                }
            }
        )


def test_role_seed_file_rejects_wildcard_mixed_with_explicit_scopes() -> None:
    """'*' means 'every supported scope' -- mixing it with explicit
    scopes in the same list is ambiguous and must be rejected."""
    with pytest.raises(ValidationError, match="only entry"):
        RoleSeedFile.model_validate(
            {
                "roles": {
                    "visitor": {"description": "x", "permissions": []},
                    "admin": {
                        "description": "y",
                        "permissions": ["*", "posts:write"],
                    },
                }
            }
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_ensure_default_roles_reads_permissions_from_file(
    tmp_path: Path, monkeypatch, session: AsyncSession
) -> None:
    """`ensure_default_roles` grants exactly the permissions listed in
    the seed file, including a custom third role -- proving roles are
    driven by data, not by a hardcoded VISITOR_ROLE/ADMIN_ROLE branch
    in Python."""
    import kalekit.auth.seed as seed_module

    custom_file = tmp_path / "roles.yaml"
    custom_file.write_text(
        textwrap.dedent(
            """\
            roles:
              visitor:
                description: "Default role for new sign-ups"
                permissions: []
              admin:
                description: "Full access"
                permissions: ["*"]
              editor:
                description: "Can write posts"
                permissions: ["posts:write"]
            """
        )
    )
    monkeypatch.setattr(seed_module, "ROLE_SEED_FILE", custom_file)

    visitor, admin = await ensure_default_roles(session)

    editor_result = await session.execute(select(Role).where(Role.name == "editor"))
    editor = editor_result.scalar_one()

    editor_permissions = (
        await session.execute(
            select(RolePermission).where(RolePermission.role_id == editor.id)
        )
    ).scalars().all()
    assert len(editor_permissions) == 1

    admin_permissions = (
        await session.execute(
            select(RolePermission).where(RolePermission.role_id == admin.id)
        )
    ).scalars().all()
    assert len(admin_permissions) == len(SCOPES_SUPPORTED)

    visitor_permissions = (
        await session.execute(
            select(RolePermission).where(RolePermission.role_id == visitor.id)
        )
    ).scalars().all()
    assert len(visitor_permissions) == 0


@pytest.mark.asyncio(loop_scope="session")
async def test_ensure_default_roles_reconciles_new_permissions_on_rerun(
    tmp_path: Path, monkeypatch, session: AsyncSession
) -> None:
    """A permission added to `roles.yaml` for an *already-seeded* role
    must be granted the next time `ensure_default_roles` runs -- it
    must not early-return just because the role already has some
    permissions, which would make editing the file after first seed a
    no-op and contradict the file's own claim that editing it and
    redeploying is enough to change what a role can do."""
    import kalekit.auth.seed as seed_module

    seed_file = tmp_path / "roles.yaml"
    seed_file.write_text(
        textwrap.dedent(
            """\
            roles:
              visitor:
                description: "Default role for new sign-ups"
                permissions: []
              admin:
                description: "Full access"
                permissions: ["*"]
              editor:
                description: "Can write posts"
                permissions: ["posts:write"]
            """
        )
    )
    monkeypatch.setattr(seed_module, "ROLE_SEED_FILE", seed_file)

    await ensure_default_roles(session)

    editor = (
        await session.execute(select(Role).where(Role.name == "editor"))
    ).scalar_one()
    first_run_permissions = (
        await session.execute(
            select(RolePermission).where(RolePermission.role_id == editor.id)
        )
    ).scalars().all()
    assert len(first_run_permissions) == 1

    # Simulate editing the file and redeploying: editor now also gets
    # posts:read.
    seed_file.write_text(
        textwrap.dedent(
            """\
            roles:
              visitor:
                description: "Default role for new sign-ups"
                permissions: []
              admin:
                description: "Full access"
                permissions: ["*"]
              editor:
                description: "Can write posts"
                permissions: ["posts:write", "posts:read"]
            """
        )
    )

    await ensure_default_roles(session)

    second_run_permissions = (
        await session.execute(
            select(RolePermission).where(RolePermission.role_id == editor.id)
        )
    ).scalars().all()
    assert len(second_run_permissions) == 2


@pytest.mark.asyncio(loop_scope="session")
async def test_ensure_default_roles_reconciles_description_on_rerun(
    tmp_path: Path, monkeypatch, session: AsyncSession
) -> None:
    """A role's `description` edited in `roles.yaml` after first seed
    must be picked up on the next `ensure_default_roles` run -- it must
    not stick with whatever description the role had the first time it
    was created, the same reconciliation promise already honored for
    permissions."""
    import kalekit.auth.seed as seed_module

    seed_file = tmp_path / "roles.yaml"
    seed_file.write_text(
        textwrap.dedent(
            """\
            roles:
              visitor:
                description: "Default role for new sign-ups"
                permissions: []
              admin:
                description: "Full access"
                permissions: ["*"]
              editor:
                description: "Can write posts"
                permissions: ["posts:write"]
            """
        )
    )
    monkeypatch.setattr(seed_module, "ROLE_SEED_FILE", seed_file)

    await ensure_default_roles(session)

    editor = (
        await session.execute(select(Role).where(Role.name == "editor"))
    ).scalar_one()
    assert editor.description == "Can write posts"

    # Simulate editing the file and redeploying: editor's description
    # changes.
    seed_file.write_text(
        textwrap.dedent(
            """\
            roles:
              visitor:
                description: "Default role for new sign-ups"
                permissions: []
              admin:
                description: "Full access"
                permissions: ["*"]
              editor:
                description: "Can write and edit posts"
                permissions: ["posts:write"]
            """
        )
    )

    await ensure_default_roles(session)

    await session.refresh(editor)
    assert editor.description == "Can write and edit posts"
