from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import require_permission
from kalekit.chat.repository import create_message, list_messages
from kalekit.chat.schemas import (
    ChatMessageCreate,
    ChatMessageListResponse,
    ChatMessageResponse,
)
from kalekit.models.user import User
from kalekit.postgres import get_db_session

router = APIRouter(prefix="/chat", tags=["chat"])


@router.get("/", response_model=ChatMessageListResponse)
async def get_messages(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _caller: Annotated[User, Depends(require_permission("posts:read"))],
) -> ChatMessageListResponse:
    messages, total = await list_messages(session)
    return ChatMessageListResponse(
        items=[ChatMessageResponse.model_validate(m) for m in messages],
        total=total,
    )


@router.post("/", response_model=ChatMessageResponse, status_code=201)
async def post_message(
    body: ChatMessageCreate,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    caller: Annotated[User, Depends(require_permission("posts:write"))],
) -> ChatMessageResponse:
    message = await create_message(session, user_id=caller.id, content=body.content)
    return ChatMessageResponse.model_validate(message)
