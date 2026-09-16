from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import (
    OrgActor,
    require_org_member,
    require_org_permission,
)
from kalekit.auth.roles import role_has_permission
from kalekit.chat.repository import (
    create_message,
    delete_message,
    get_message,
    list_messages,
)
from kalekit.chat.schemas import (
    ChatMessageCreate,
    ChatMessageListResponse,
    ChatMessageResponse,
)
from kalekit.models.user import User
from kalekit.postgres import get_db_session

router = APIRouter(prefix="/organizations/{organization_id}/chat", tags=["chat"])


@router.get("/", response_model=ChatMessageListResponse)
async def get_messages(
    organization_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _caller: Annotated[User, Depends(require_org_member)],
) -> ChatMessageListResponse:
    """Any role, including viewer, can read."""
    messages, total = await list_messages(session, organization_id=organization_id)
    return ChatMessageListResponse(
        items=[ChatMessageResponse.model_validate(m) for m in messages],
        total=total,
    )


@router.post("/", response_model=ChatMessageResponse, status_code=201)
async def post_message(
    organization_id: UUID,
    body: ChatMessageCreate,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[OrgActor, Depends(require_org_permission("chat:write"))],
) -> ChatMessageResponse:
    """Posting needs `chat:write` — a `viewer` is refused."""
    message = await create_message(
        session,
        organization_id=organization_id,
        user_id=caller.user.id,
        content=body.content,
    )
    return ChatMessageResponse.model_validate(message)


@router.delete("/{message_id}", status_code=204)
async def delete_message_endpoint(
    organization_id: UUID,
    message_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[OrgActor, Depends(require_org_permission("chat:read"))],
) -> None:
    """Deleting needs `chat:delete` — *or* being the message's own author.

    This is the ABAC-inside-Hybrid case: the role-based gate above only
    establishes membership (every role has `chat:read`), and the real
    authorization decision — is this caller allowed to delete *this*
    message? — happens below, once the message is loaded, by comparing
    against a *value on the record* (its author) rather than a role.
    """
    message = await get_message(
        session, organization_id=organization_id, message_id=message_id
    )
    if message is None:
        raise HTTPException(status_code=404, detail="Not found")
    is_author = message.user_id == caller.user.id
    if not is_author and not role_has_permission(caller.role, "chat:delete"):
        raise HTTPException(
            status_code=403,
            detail="Requires the 'chat:delete' permission or message authorship",
        )
    await delete_message(session, message=message)
