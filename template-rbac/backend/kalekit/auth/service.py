import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext

from kalekit.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# A precomputed bcrypt hash with no corresponding user, used to keep the
# login timing profile identical whether or not the submitted email exists.
# Without this, `find_user_by_email` returning None would let login skip
# the (comparatively slow) hash verification entirely, letting an attacker
# distinguish "no such account" from "wrong password" by response time.
DUMMY_PASSWORD_HASH = "$2b$12$r2hOOyYQYASRXa2Vqre.AOXMiIKvq3fD3lvQnT6Pm8qx7hRVqppxS"


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


def generate_refresh_token() -> tuple[str, datetime]:
    """Returns (raw_token, expires_at).

    Refresh tokens are opaque `secrets.token_urlsafe` values, not JWTs.
    Unlike a JWT (which is self-describing and can't be looked up once
    hashed with a salted algorithm like bcrypt), an opaque token's hash
    can be looked up directly in the `refresh_tokens` table -- that's
    what lets /auth/refresh actually validate against the DB (checking
    revocation, rotation, and reuse) instead of only checking a
    signature and expiry. See hash_refresh_token below.
    """
    token = secrets.token_urlsafe(32)
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    return token, expire


def hash_refresh_token(raw_token: str) -> str:
    """SHA-256 hex digest, used as the lookup key in `refresh_tokens`.

    Unlike bcrypt (salted, one-way, not look-up-able), a plain SHA-256
    digest of a high-entropy opaque token is deterministic and safe to
    index/query on: the token itself has 256 bits of randomness, so the
    digest isn't vulnerable to precomputation/rainbow-table attacks the
    way a hash of a low-entropy secret (like a password) would be.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
