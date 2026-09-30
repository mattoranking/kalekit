from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.dependencies import require_admin_permission
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.user.repository import list_roles
from kalekit.user.schemas import RoleListResponse, RoleResponse

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get(
    "",
    response_model=RoleListResponse,
    summary="List the roles and their permissions",
)
async def get_roles(
    session: Annotated[AsyncSession, Depends(get_db_session, scope="function")],
    _caller: Annotated[User, Depends(require_admin_permission("roles:read"))],
) -> RoleListResponse:
    # Read from the database, not roles.yaml: a role added only in the
    # database shows up here. The set is small, so there is no paging.
    roles = await list_roles(session)
    return RoleListResponse(
        items=[
            RoleResponse(
                name=role.name,
                description=role.description,
                permissions=sorted(rp.permission.name for rp in role.permissions),
            )
            for role in roles
        ]
    )
