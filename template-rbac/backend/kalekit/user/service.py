from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.seed import ADMIN_ROLE
from kalekit.models.role import Role, UserRole
from kalekit.models.user import User


async def ensure_not_last_active_admin(session: AsyncSession, user: User) -> None:
    """Refuse (409) when `user` is the only active holder of the admin
    role, so a change that takes the role or the account away from them
    would leave nobody able to manage users.

    Call it before deactivating `user` or removing their admin role. A
    user who is not an active admin is never the last one, so the call
    passes for them.

    The active admins are read `FOR UPDATE`: two requests that each take
    one of the last two admins away serialise on those rows, so the
    second sees the first one's change and is refused, instead of both
    passing the check.
    """
    result = await session.execute(
        select(User.id)
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(Role.name == ADMIN_ROLE, User.is_active.is_(True))
        .with_for_update(of=User)
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
    changed, False when it was already that set (nothing is written)."""
    wanted = {role.id for role in new_roles}
    current = {ur.role_id: ur for ur in user.roles}
    if wanted == set(current):
        return False
    for role_id, user_role in current.items():
        if role_id not in wanted:
            await session.delete(user_role)
    for role_id in wanted - set(current):
        session.add(UserRole(user_id=user.id, role_id=role_id))
    await session.flush()
    await session.refresh(user, ["roles"])
    return True
