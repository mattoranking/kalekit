from fastapi import APIRouter

from kalekit.auth.endpoints import router as auth_router
from kalekit.chat.endpoints import router as chat_router
from kalekit.oauth.endpoints import router as oauth_router
from kalekit.organization.endpoints import (
    invitation_router as organization_invitation_router,
)
from kalekit.organization.endpoints import member_router as organization_member_router
from kalekit.organization.endpoints import router as organization_router

router = APIRouter(prefix="/v1")

# /auth
router.include_router(auth_router)
# /oauth
router.include_router(oauth_router)
# /organizations
router.include_router(organization_router)
# /organizations/{organization_id}/members, /organizations/{organization_id}/invitations
router.include_router(organization_member_router)
# /invitations/accept
router.include_router(organization_invitation_router)
# /organizations/{organization_id}/chat
router.include_router(chat_router)
