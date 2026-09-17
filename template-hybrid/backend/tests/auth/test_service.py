import hashlib

import jwt

from kalekit.auth.service import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from kalekit.config import settings


def test_generate_refresh_token_is_opaque_and_not_a_jwt() -> None:
    """Refresh tokens must be opaque secrets, not JWTs -- a JWT is
    self-describing and can be decoded without ever touching the DB,
    which is exactly the property #3 needed to close."""
    token, expires_at = generate_refresh_token()

    assert token
    assert expires_at is not None
    # A JWT always has two dots (header.payload.signature); an opaque
    # token from secrets.token_urlsafe never does.
    assert token.count(".") == 0


def test_hash_refresh_token_is_deterministic_sha256() -> None:
    token = "some-raw-refresh-token"
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()

    assert hash_refresh_token(token) == expected
    # Deterministic -- unlike bcrypt, so it can be looked up by hash.
    assert hash_refresh_token(token) == hash_refresh_token(token)


def test_hash_refresh_token_differs_for_different_tokens() -> None:
    assert hash_refresh_token("token-a") != hash_refresh_token("token-b")


def test_create_access_token_is_a_pyjwt_token() -> None:
    """Access tokens are still JWTs (unlike refresh tokens), signed and
    decodable via PyJWT rather than the removed python-jose."""
    token = create_access_token("user-123")

    payload = jwt.decode(
        token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
    )
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"
    assert "jti" in payload
