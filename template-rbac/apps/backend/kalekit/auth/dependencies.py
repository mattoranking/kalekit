from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.config import settings
from kalekit.models.user import User
from kalekit.postgres import get_db_session
from kalekit.auth.permissions import get_permissions_for_roles

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_permission(permission: str):
    """Dependency factory for RBAC checks."""

    async def checker(
        user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        roles = [ur.role.name for ur in user.roles]
        user_permissions = await get_permissions_for_roles(roles)
        if permission not in user_permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Missing permission: {permission}",
            )
        return user

    return checker
