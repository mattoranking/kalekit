import uuid

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.chat.models import ChatMessage
from kalekit.utils.db.tenancy import tenant_filter, tenant_select


def get_readable_statement(organization_id: uuid.UUID) -> Select:
    """Ownership filter: only messages belonging to this organization.

    This is the ABAC-inside-Hybrid gate itself — there's no separate
    permission lookup here, just tenant scope. Mirrors the pattern real
    multi-tenant products (e.g. Polar) use: the tenant check lives in
    the query, not in a decorator. Built via `tenant_select()` so the
    filter can't be typo'd or dropped by hand.
    """
    return tenant_select(ChatMessage, organization_id=organization_id)


async def list_messages(
    session: AsyncSession, *, organization_id: uuid.UUID, limit: int = 50
) -> tuple[list[ChatMessage], int]:
    total_q = await session.execute(
        select(func.count(ChatMessage.id)).where(
            tenant_filter(ChatMessage, organization_id=organization_id)
        )
    )
    total = total_q.scalar_one()

    result = await session.execute(
        get_readable_statement(organization_id)
        .order_by(ChatMessage.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all()), total


async def create_message(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    content: str,
) -> ChatMessage:
    message = ChatMessage(
        organization_id=organization_id, user_id=user_id, content=content
    )
    session.add(message)
    await session.flush()
    return message


async def get_message(
    session: AsyncSession, *, organization_id: uuid.UUID, message_id: uuid.UUID
) -> ChatMessage | None:
    result = await session.execute(
        get_readable_statement(organization_id).where(ChatMessage.id == message_id)
    )
    return result.scalar_one_or_none()


async def delete_message(session: AsyncSession, *, message: ChatMessage) -> None:
    await session.delete(message)
    await session.flush()
