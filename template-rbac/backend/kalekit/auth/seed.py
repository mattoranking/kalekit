from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.scope import SCOPES_SUPPORTED
from kalekit.models.role import Permission, Role, RolePermission, UserRole
from kalekit.models.user import User

VISITOR_ROLE = "visitor"
ADMIN_ROLE = "admin"


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


async def ensure_default_roles(session: AsyncSession) -> tuple[Role, Role]:
    """Create the starter kit's default roles on first use.

    `visitor` is granted to everyone who signs up and carries no
    permissions. `admin` carries every permission the Scope enum
    defines, so there's a working example the moment the first user
    registers — there is no separate seed script or admin invite flow.
    """
    visitor = await _get_or_create_role(
        session, VISITOR_ROLE, "Default role for new sign-ups"
    )
    admin = await _get_or_create_role(session, ADMIN_ROLE, "Full access")

    existing = await session.execute(
        select(RolePermission).where(RolePermission.role_id == admin.id)
    )
    if existing.first() is None:
        # Same race as the role/permission lookups above: two concurrent
        # first-time registrations can both see "no permissions granted
        # to admin yet" and both try to populate the join table. Only
        # one wins the (role_id, permission_id) primary key; the loser
        # rolls back to the savepoint and treats the conflict as
        # "someone else already did this" rather than a hard failure.
        try:
            async with session.begin_nested():
                for scope in SCOPES_SUPPORTED:
                    permission = await _get_or_create_permission(session, scope)
                    session.add(
                        RolePermission(role_id=admin.id, permission_id=permission.id)
                    )
                await session.flush()
        except IntegrityError:
            pass

    return visitor, admin


async def assign_role(session: AsyncSession, user: User, role: Role) -> None:
    session.add(UserRole(user_id=user.id, role_id=role.id))
    await session.flush()
