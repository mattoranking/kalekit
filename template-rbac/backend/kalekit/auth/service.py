import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext

from kalekit.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def generate_verification_token() -> str:
    """A high-entropy, URL-safe random token to email the user."""
    return secrets.token_urlsafe(32)


def hash_verification_token(token: str) -> str:
    """sha256, not bcrypt: this token is already a 256-bit random
    secret (not a low-entropy human password), so bcrypt's slow work
    factor buys nothing -- a fast, deterministic hash is the right
    tool, and it lets us look the token up by its hash directly."""
    return hashlib.sha256(token.encode()).hexdigest()


def verification_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(
        hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
    )


def create_access_token(
    user_id: str,
    scopes: list[str],
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload: dict[str, Any] = {
        "sub": user_id,
        "jti": str(uuid.uuid4()),
        "scopes": scopes,
        "type": "access",
        "exp": expire,
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(user_id: str) -> tuple[str, datetime]:
    """Returns (raw_token, expires_at)."""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload: dict[str, Any] = {
        "sub": user_id,
        "exp": expire,
        "type": "refresh",
    }
    token = jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return token, expire
