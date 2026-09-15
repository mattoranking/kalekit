from fastapi import APIRouter

from kalekit.auth.endpoints import router as auth_router
from kalekit.chat.endpoints import router as chat_router
from kalekit.oauth.endpoints import router as oauth_router
from kalekit.user.endpoints import router as user_router

router = APIRouter(prefix="/v1")

# /auth
router.include_router(auth_router)
# /oauth
router.include_router(oauth_router)
# /users
router.include_router(user_router)
# /chat
router.include_router(chat_router)
