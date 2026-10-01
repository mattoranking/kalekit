import uuid

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import (
    bump_token_version,
    carry_refresh_token_versions,
)
from kalekit.auth.seed import ADMIN_ROLE, is_unique_violation
from kalekit.models.role import Role, UserRole
from kalekit.models.user import User
from kalekit.user.repository import get_roles_by_name, get_user_by_id

# Key of the Postgres advisory lock that serialises every change to who is
# an active admin (arbitrary constant, unique to this lock).
_ADMIN_CHANGE_LOCK_KEY = 7_234_001


async def lock_admin_changes(session: AsyncSession) -> None:
    """Wait for, then hold until the transaction ends, the lock that every
    change to who is an active admin must take.

    Row locks are not enough here. A role change deletes a `user_roles`
    row and a suspension updates a `users` row, and Postgres re-checks
    only the rows a waiting query locked, so a second request that waited
    on the first still counts the admin role row the first one deleted. One
    lock for all of them makes the second request start its reads only
    after the first has committed. Reads made after this call see the
    committed state (READ COMMITTED takes a new snapshot per statement).
    """
    await session.execute(select(func.pg_advisory_xact_lock(_ADMIN_CHANGE_LOCK_KEY)))


async def ensure_not_last_active_admin(session: AsyncSession, user: User) -> None:
    """Refuse (409) when `user` is the only active holder of the admin
    role, so a change that takes the role or the account away from them
    would leave nobody able to manage users.

    Call it before deactivating `user` or removing their admin role, and
    commit that change in the same transaction: the call takes the admin
    change lock (see `lock_admin_changes`), so two overlapping requests
    that each take one of the last two admins away run one after the
    other, and the second is refused. A user who is not an active admin is
    never the last one, so the call passes for them.
    """
    await lock_admin_changes(session)
    result = await session.execute(
        select(User.id)
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(Role.name == ADMIN_ROLE, User.is_active.is_(True))
    )
    active_admin_ids = set(result.scalars().all())
    if active_admin_ids == {user.id}:
        raise HTTPException(
            status_code=409,
            detail="Cannot remove the last active admin",
        )


async def replace_user_roles(
    session: AsyncSession, user: User, new_roles: list[Role]
) -> bool:
    """Make `user` hold exactly `new_roles`. Returns True when the set
    changed, False when it was already that set (nothing is written).

    An insert that hits the unique (user, role) constraint means another
    request added the row first. It is skipped (each insert runs in its own
    savepoint) and does not count as a change made here."""
    wanted = {role.id for role in new_roles}
    current: dict[uuid.UUID, UserRole] = {}
    changed = False
    for user_role in user.roles:
        if user_role.role_id not in wanted:
            # Every row of an unwanted role, duplicates included.
            await session.delete(user_role)
            changed = True
        elif user_role.role_id in current:
            # A database created before the unique (user, role) constraint
            # (no migrations add it) may hold a second row. Drop it.
            await session.delete(user_role)
        else:
            current[user_role.role_id] = user_role
    for role_id in wanted - set(current):
        try:
            async with session.begin_nested():
                session.add(UserRole(user_id=user.id, role_id=role_id))
                await session.flush()
            changed = True
        except IntegrityError as exc:
            if not is_unique_violation(exc):
                raise
    await session.flush()
    # Re-read always: a skipped insert leaves a row `user.roles` lacks.
    await session.refresh(user, ["roles"])
    return changed


async def change_user_roles(
    session: AsyncSession,
    *,
    caller: User,
    user_id: uuid.UUID,
    role_names: set[str],
) -> User:
    """Replace the roles `user_id` holds with `role_names`, for PUT
    /v1/users/{id}/roles. Raises 404 (no such user), 422 (unknown role
    name) or 409 (removing the caller's own admin role, or the last active
    admin's). Bumps the token version when the set changed, so the user's
    old tokens, which carry the old `scopes`, stop working."""
    # One role change at a time: the admin checks below need to see the
    # previous change's result. (A double click's second insert would hit
    # the unique (user, role) constraint, which replace_user_roles skips.)
    await lock_admin_changes(session)

    user = await get_user_by_id(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # The session may already hold this user (as the caller) with roles
    # read before the lock was taken.
    await session.refresh(user, ["roles"])

    roles = await get_roles_by_name(session, role_names)
    unknown = sorted(role_names - {role.name for role in roles})
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown role(s): {', '.join(unknown)}",
        )

    holds_admin = ADMIN_ROLE in {ur.role.name for ur in user.roles}
    if holds_admin and ADMIN_ROLE not in role_names:
        if user.id == caller.id:
            raise HTTPException(
                status_code=409,
                detail="You cannot remove your own admin role",
            )
        await ensure_not_last_active_admin(session, user)

    # TODO(#219): record_event(...)
    if await replace_user_roles(session, user, roles):
        # No invalidate_role_cache: that cache holds what each role may
        # do, which did not change, and the user's roles are re-read on
        # every request. No user-wide Redis block either: #229 removed it.
        await bump_token_version(session, user)
        # Sessions survive a role change, so their refresh tokens follow
        # the new version (#240).
        await carry_refresh_token_versions(session, user)
    return user
