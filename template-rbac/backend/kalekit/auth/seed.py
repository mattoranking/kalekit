from pathlib import Path

import yaml
from pydantic import BaseModel, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.scope import SCOPES_SUPPORTED
from kalekit.models.role import Permission, Role, RolePermission, UserRole
from kalekit.models.user import User

VISITOR_ROLE = "visitor"
ADMIN_ROLE = "admin"

# Checked-in seed data for `ensure_default_roles` -- see the file itself
# for the format and the rationale (issue #2: seed-managed, not an admin
# UI, for this template's single-tenant shape).
ROLE_SEED_FILE = Path(__file__).parent / "roles.yaml"

# Sentinel meaning "every scope currently supported by the app" in a
# role's `permissions` list, instead of spelling out every scope.
ALL_SCOPES_WILDCARD = "*"


class RoleDefinition(BaseModel):
    description: str
    permissions: list[str]


class RoleSeedFile(BaseModel):
    roles: dict[str, RoleDefinition]

    @model_validator(mode="after")
    def _validate_permissions(self) -> "RoleSeedFile":
        """Every role's `permissions` must be exactly `["*"]`, or a list
        of known, non-duplicated scopes -- not a mix of the wildcard
        with explicit scopes, not a typo'd scope string, and not the
        same scope listed twice (a duplicate would make
        `_ensure_role_permissions`'s insert loop attempt two identical
        `RolePermission` rows in the same `begin_nested()`, which fails
        the primary key and silently rolls back every other permission
        grant in that call). This file is the security-sensitive source
        of truth `ensure_default_roles` grants from, so a bad entry
        should fail loudly here rather than silently no-op at the DB
        layer.
        """
        supported = set(SCOPES_SUPPORTED)
        for name, definition in self.roles.items():
            permissions = definition.permissions
            if permissions == [ALL_SCOPES_WILDCARD]:
                continue
            if ALL_SCOPES_WILDCARD in permissions:
                raise ValueError(
                    f"role '{name}': '{ALL_SCOPES_WILDCARD}' must be the "
                    "only entry in `permissions` when used -- it cannot be "
                    f"mixed with explicit scopes, got {permissions!r}"
                )
            unknown = sorted(set(permissions) - supported)
            if unknown:
                raise ValueError(
                    f"role '{name}' lists permission(s) not in "
                    f"SCOPES_SUPPORTED: {unknown!r} "
                    f"(valid values: {sorted(supported)!r})"
                )
            if len(permissions) != len(set(permissions)):
                duplicates = sorted(
                    {p for p in permissions if permissions.count(p) > 1}
                )
                raise ValueError(
                    f"role '{name}' lists duplicate permission(s): "
                    f"{duplicates!r} -- each permission must appear at "
                    "most once"
                )
        return self


def _load_role_definitions() -> dict[str, RoleDefinition]:
    """Parse `roles.yaml` into role definitions.

    Re-read (not cached) on every call: the file is tiny, this only
    runs on registration/OAuth-signup/admin-creation paths (not hot
    request paths), and not caching keeps this function's behavior
    predictable if the file is ever swapped out between calls (e.g.
    in tests).
    """
    with ROLE_SEED_FILE.open() as f:
        raw = yaml.safe_load(f)

    seed_file = RoleSeedFile.model_validate(raw)

    for required in (VISITOR_ROLE, ADMIN_ROLE):
        if required not in seed_file.roles:
            raise ValueError(
                f"{ROLE_SEED_FILE} is missing required role '{required}'"
            )

    return seed_file.roles


async def _get_or_create_role(
    session: AsyncSession, name: str, description: str
) -> Role:
    result = await session.execute(select(Role).where(Role.name == name))
    role = result.scalar_one_or_none()
    if role is not None:
        return role

    # `ensure_default_roles` runs on every /auth/register and OAuth
    # signup, so two concurrent first-time registrations against a
    # fresh database can both see "no role yet" here and both attempt
    # the insert. Only one wins the DB-unique `name` constraint -- the
    # loser rolls back to the savepoint (not the whole request's
    # transaction, which may already hold other flushed work, e.g. the
    # just-created User) and re-selects the row the winner committed.
    try:
        async with session.begin_nested():
            role = Role(name=name, description=description)
            session.add(role)
            await session.flush()
    except IntegrityError:
        result = await session.execute(select(Role).where(Role.name == name))
        role = result.scalar_one_or_none()
        if role is None:
            raise
    return role


async def _get_or_create_permission(session: AsyncSession, name: str) -> Permission:
    result = await session.execute(select(Permission).where(Permission.name == name))
    permission = result.scalar_one_or_none()
    if permission is not None:
        return permission

    # Same concurrent-insert race as `_get_or_create_role` above.
    try:
        async with session.begin_nested():
            permission = Permission(name=name)
            session.add(permission)
            await session.flush()
    except IntegrityError:
        result = await session.execute(
            select(Permission).where(Permission.name == name)
        )
        permission = result.scalar_one_or_none()
        if permission is None:
            raise
    return permission


async def _ensure_role_permissions(
    session: AsyncSession, role: Role, permission_names: list[str]
) -> None:
    """Grant `role` every permission in `permission_names` it doesn't
    already have.

    This reconciles rather than only acting on a never-seeded role: a
    role that was seeded before with a smaller permission list (or
    before a `Scope` this role's `"*"` wildcard now covers existed)
    picks up the newly-added permissions the next time this runs,
    matching `roles.yaml`'s own claim that editing it and redeploying
    is enough to change what a role can do. Permissions removed from
    the file are deliberately left alone -- additive-only, consistent
    with the rest of this module only ever adding rows.
    """
    if not permission_names:
        return

    existing = await session.execute(
        select(Permission.name)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role.id)
    )
    already_granted = set(existing.scalars().all())
    missing = [name for name in permission_names if name not in already_granted]
    if not missing:
        return

    # Same race as the role/permission lookups above: two concurrent
    # callers can both compute the same "missing" set and both try to
    # populate the join table. Only one wins the (role_id,
    # permission_id) primary key; the loser rolls back to the savepoint
    # and treats the conflict as "someone else already did this" rather
    # than a hard failure -- the next call to this function will see
    # the winner's rows and compute a smaller (or empty) `missing` set.
    try:
        async with session.begin_nested():
            for scope in missing:
                permission = await _get_or_create_permission(session, scope)
                session.add(
                    RolePermission(role_id=role.id, permission_id=permission.id)
                )
            await session.flush()
    except IntegrityError:
        pass


async def ensure_default_roles(session: AsyncSession) -> tuple[Role, Role]:
    """Create the starter kit's default roles on first use.

    Role/permission definitions come from the checked-in `roles.yaml`
    (see `_load_role_definitions`), not hardcoded Python -- changing
    what a role can do means editing that file and redeploying, not
    this function. `visitor` is granted to everyone who signs up and
    carries no permissions by default. `admin` carries every permission
    the Scope enum defines, so there's a working example the moment the
    first user registers -- there is no separate seed script or admin
    invite flow.

    Also runs against a database that was already seeded by an earlier
    version of `roles.yaml`: `_ensure_role_permissions` grants any
    permission the file now lists for a role that it doesn't already
    have, so a permission added to the file after a role's first seed
    still takes effect on redeploy.
    """
    definitions = _load_role_definitions()

    roles: dict[str, Role] = {}
    for name, definition in definitions.items():
        roles[name] = await _get_or_create_role(session, name, definition.description)

    for name, definition in definitions.items():
        permission_names = (
            SCOPES_SUPPORTED
            if definition.permissions == [ALL_SCOPES_WILDCARD]
            else definition.permissions
        )
        await _ensure_role_permissions(session, roles[name], permission_names)

    return roles[VISITOR_ROLE], roles[ADMIN_ROLE]


async def assign_role(session: AsyncSession, user: User, role: Role) -> None:
    session.add(UserRole(user_id=user.id, role_id=role.id))
    await session.flush()
