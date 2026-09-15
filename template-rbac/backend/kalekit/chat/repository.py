import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.chat.models import ChatMessage


async def list_messages(
    session: AsyncSession, *, limit: int = 50
) -> tuple[list[ChatMessage], int]:
    total_q = await session.execute(select(func.count(ChatMessage.id)))
    total = total_q.scalar_one()

    result = await session.execute(
        select(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(limit)
    )
    return list(result.scalars().all()), total


async def create_message(
    session: AsyncSession, *, user_id: uuid.UUID, content: str
) -> ChatMessage:
    message = ChatMessage(user_id=user_id, content=content)
    session.add(message)
    await session.flush()
    return message
