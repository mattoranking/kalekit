import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

from kalekit.auth.client_type import ClientType
from kalekit.config import settings

# Argon2 is the preferred scheme for new hashes (per current FastAPI
# docs); bcrypt is kept as a second, verify-only hasher purely so
# accounts created before this migration -- whose password_hash is
# still a bcrypt hash -- keep working. See verify_and_upgrade_password
# for how those get transparently moved onto Argon2 on next login.
password_hash = PasswordHash([Argon2Hasher(), BcryptHasher()])

# A precomputed hash with no corresponding user, used to keep the login
# timing profile identical whether or not the submitted email exists.
# Without this, `find_user_by_email` returning None would let login skip
# the (comparatively slow) hash verification entirely, letting an attacker
# distinguish "no such account" from "wrong password" by response time.
#
# This must stay an Argon2 hash (the same scheme `hash_password` now
# produces for every new/upgraded account) rather than the bcrypt hash
# used before this migration -- verifying against a different algorithm
# than the common case would reintroduce a timing side-channel of its
# own (unknown-email requests bcrypt-timed vs. real-account requests
# Argon2-timed) if the two algorithms' wall-clock cost differs.
# Hardcoded rather than computed at import time to avoid adding
# startup-time variance.
#
# Note this doesn't make login fully constant-time during the
# migration window itself: an existing account whose hash hasn't yet
# been upgraded (see verify_and_upgrade_password) is still verified
# against bcrypt, not Argon2, until its next successful login. That's
# an inherent, unavoidable side effect of migrating hash algorithms in
# place, not something a single dummy-hash choice can fix -- matching
# the new default here is still the right call for the steady state.
DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4"
    "$trD9/9MVHdqUHmI1ujzBGQ$sYhVtOBGIDR2cGcALLbDhC/z7xMEdMVZh6Ui8NNDJzY"
)


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    valid, _ = password_hash.verify_and_update(plain, hashed)
    return valid


def verify_and_upgrade_password(plain: str, hashed: str) -> tuple[bool, str | None]:
    """Verify `plain` against `hashed`, same as verify_password, but also
    return a re-hash under the current preferred scheme (Argon2) when
    `hashed` used an older/non-preferred scheme -- e.g. a bcrypt hash
    from before this migration. The caller (login) should persist the
    returned hash when it isn't None, so legacy accounts are upgraded
    transparently instead of needing a password reset."""
    return password_hash.verify_and_update(plain, hashed)


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


def password_reset_token_expiry() -> datetime:
    """Password-reset tokens get their own (much shorter) expiry than
    email-verification tokens -- they authorize an account takeover if
    intercepted, not just an email-ownership proof, so the window a
    leaked/intercepted link stays valid should be minutes, not hours.
    The raw token itself is generated and hashed exactly like an
    email-verification token (`generate_verification_token` /
    `hash_verification_token` -- both already generic over what kind of
    token they're producing/hashing), so only the expiry duration
    differs."""
    return datetime.now(timezone.utc) + timedelta(
        minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    )


def create_access_token(
    user_id: str,
    scopes: list[str],
    client: ClientType = ClientType.web,
    session_id: str | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes(client)
    )
    payload: dict[str, Any] = {
        "sub": user_id,
        "jti": str(uuid.uuid4()),
        "scopes": scopes,
        "type": "access",
        "exp": expire,
        # Which client this token was minted for -- see
        # kalekit.auth.client_type.ClientType and #6. Pinning it (rather
        # than a single fixed audience) is what lets admin-only routes
        # (require_admin_client) reject a token minted for web/mobile
        # even when its baked-in scopes include admin permissions.
        "aud": client.value,
    }
    # `session_id` is the refresh token family this access token was
    # minted from (see kalekit.auth.repository.store_refresh_token /
    # RefreshToken.family_id). It's what lets /auth/sessions mark the
    # caller's own session as "current" and lets a single session be
    # revoked (block_family_tokens) without blocking every session the
    # user has. Not every access token has one -- register/service
    # tokens outside the login/refresh/oauth flows don't -- so it's
    # optional and get_current_user treats a missing sid as "not tied
    # to any session" rather than an error.
    if session_id is not None:
        payload["sid"] = session_id
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
        # `kid` identifies which key signed this token, so a secret can
        # be rotated (new JWT_SECRET_KEY + JWT_KID, old one moved into
        # JWT_PREVIOUS_KEYS) without invalidating tokens already issued
        # under the previous key. See _decode_access_token.
        headers={"kid": settings.JWT_KID},
    )


def generate_refresh_token(client: ClientType = ClientType.web) -> tuple[str, datetime]:
    """Returns (raw_token, expires_at).

    Refresh tokens are opaque `secrets.token_urlsafe` values, not JWTs.
    Unlike a JWT (which is self-describing and can't be looked up once
    hashed with a salted algorithm like bcrypt), an opaque token's hash
    can be looked up directly in the `refresh_tokens` table -- that's
    what lets /auth/refresh actually validate against the DB (checking
    revocation, rotation, and reuse) instead of only checking a
    signature and expiry. See hash_refresh_token below.

    `expires_at` is the sliding *idle* timeout for `client` (see
    kalekit.config.Settings.session_idle_timeout) -- every successful
    refresh calls this again and gets a fresh idle deadline, so an
    actively-used session never hits it. It's independent of the
    session's absolute timeout, which is enforced separately against
    RefreshToken.family_created_at (see #6).
    """
    token = secrets.token_urlsafe(32)
    expire = datetime.now(timezone.utc) + settings.session_idle_timeout(client)
    return token, expire


def device_info_from_user_agent(user_agent: str | None) -> str | None:
    """Best-effort device label for session listings: the User-Agent
    header, truncated to fit `refresh_tokens.device_info` (String(255)).
    There's no client/app-reported device name yet (no client binding --
    see #6), so the raw UA is the only signal available. Shared by
    /auth/login, /auth/refresh, and the OAuth callback so every session
    is captured the same way regardless of how it started."""
    return user_agent[:255] if user_agent else None


def hash_refresh_token(raw_token: str) -> str:
    """SHA-256 hex digest, used as the lookup key in `refresh_tokens`.

    Unlike bcrypt (salted, one-way, not look-up-able), a plain SHA-256
    digest of a high-entropy opaque token is deterministic and safe to
    index/query on: the token itself has 256 bits of randomness, so the
    digest isn't vulnerable to precomputation/rainbow-table attacks the
    way a hash of a low-entropy secret (like a password) would be.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
