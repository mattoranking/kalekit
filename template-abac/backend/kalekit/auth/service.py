import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext

from kalekit.config import settings
from kalekit.redis import get_redis

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload: dict[str, Any] = {
        "sub": user_id,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "exp": expire,
        "aud": settings.JWT_AUDIENCE,
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
        # `kid` identifies which key signed this token, so a secret can
        # be rotated (new JWT_SECRET_KEY + JWT_KID, old one moved into
        # JWT_PREVIOUS_KEYS) without invalidating tokens already issued
        # under the previous key. See _decode_access_token in
        # kalekit.auth.dependencies.
        headers={"kid": settings.JWT_KID},
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


# ---------------------------------------------------------------------------
# Refresh grace window: let two concurrent /auth/refresh calls presenting
# the same (about-to-be-rotated) token both get back the identical new
# pair, instead of the second one being treated as reuse.
# ---------------------------------------------------------------------------

_REFRESH_GRACE_PREFIX = "refresh_grace:"


async def cache_refresh_grace_pair(
    old_token_hash: str, payload: dict, ttl_seconds: int
) -> None:
    """Remember the (access_token, refresh_token) pair issued when
    `old_token_hash` was rotated, keyed by the token that was rotated
    away. A second caller racing in with the same old token within
    `ttl_seconds` gets this exact pair back instead of a fresh one, so
    both callers end up holding the same, single new refresh token.
    """
    if ttl_seconds <= 0:
        # A zero/negative grace period means the feature is effectively
        # disabled -- nothing to cache.
        return
    r = await get_redis()
    await r.set(
        f"{_REFRESH_GRACE_PREFIX}{old_token_hash}",
        json.dumps(payload),
        ex=ttl_seconds,
    )


async def get_cached_refresh_grace_pair(old_token_hash: str) -> dict | None:
    r = await get_redis()
    cached = await r.get(f"{_REFRESH_GRACE_PREFIX}{old_token_hash}")
    if cached is None:
        return None
    return json.loads(cached)
