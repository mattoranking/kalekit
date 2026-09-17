"""Invitation token generation/hashing, ported from RBAC's
email-verification-token pattern (RBAC template's `auth/service.py`:
`generate_verification_token` / `hash_verification_token` /
`verification_token_expiry` -- not a file in this template)."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from kalekit.config import settings


def generate_invitation_token() -> str:
    """A high-entropy, URL-safe random token to email the invitee."""
    return secrets.token_urlsafe(32)


def hash_invitation_token(token: str) -> str:
    """sha256, not bcrypt: this token is already a 256-bit random secret
    (not a low-entropy human password), so bcrypt's slow work factor
    buys nothing -- a fast, deterministic hash is the right tool, and it
    lets us look the invitation up by its hash directly."""
    return hashlib.sha256(token.encode()).hexdigest()


def invitation_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(
        hours=settings.INVITATION_TOKEN_EXPIRE_HOURS
    )


__all__ = [
    "generate_invitation_token",
    "hash_invitation_token",
    "invitation_token_expiry",
]
