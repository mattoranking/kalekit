import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.user import User


async def get_users(
    session: AsyncSession,
    *,
    page: int = 1,
    size: int = 20,
) -> tuple[list[User], int]:
    total_q = await session.execute(select(func.count(User.id)))
    total = total_q.scalar_one()

    result = await session.execute(
        select(User)
        .order_by(User.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
    )
    return list(result.scalars().all()), total


async def get_user_by_id(
    session: AsyncSession, user_id: uuid.UUID
) -> User | None:
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
