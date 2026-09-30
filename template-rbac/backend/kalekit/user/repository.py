import uuid

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from kalekit.models.role import Role, UserRole
from kalekit.models.user import User
from kalekit.user.sorting import DEFAULT_USER_SORT, UserSort, user_order_by


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def get_users(
    session: AsyncSession,
    *,
    page: int = 1,
    size: int = 20,
    q: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    sort: UserSort = DEFAULT_USER_SORT,
) -> tuple[list[User], int]:
    conditions: list[ColumnElement[bool]] = []
    if q:
        conditions.append(User.email.ilike(f"%{_escape_like(q)}%", escape="\\"))
    if role is not None:
        # EXISTS, not a join: a user with several roles must count once.
        conditions.append(
            exists().where(
                UserRole.user_id == User.id,
                UserRole.role_id == Role.id,
                Role.name == role,
            )
        )
    if is_active is not None:
        conditions.append(User.is_active.is_(is_active))

    total_q = await session.execute(select(func.count(User.id)).where(*conditions))
    total = total_q.scalar_one()

    result = await session.execute(
        select(User)
        .where(*conditions)
        .order_by(*user_order_by(sort))
        .offset((page - 1) * size)
        .limit(size)
    )
    return list(result.scalars().all()), total


async def get_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await session.get(User, user_id)


async def update_user(
    session: AsyncSession,
    user: User,
    **fields: object,
) -> User:
    for k, v in fields.items():
        if v is not None:
            setattr(user, k, v)
    await session.flush()
    return user


async def deactivate_user(session: AsyncSession, user: User) -> User:
    user.is_active = False
    await session.flush()
    return user
