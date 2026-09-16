import jwt
import pytest

from kalekit.auth.service import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    hash_password,
    verify_and_upgrade_password,
    verify_password,
)
from kalekit.config import settings

# A hash produced by the pre-migration passlib/bcrypt setup, kept here so
# tests can prove old accounts still verify (and get upgraded) after the
# switch to pwdlib/Argon2. Corresponds to the password "correct-password".
LEGACY_BCRYPT_HASH = "$2b$12$fVcEWj4wDMGN/yfRQAywQOHPaZ3rPZ40inFuNlnwkGuym1KhnL1mu"


def test_hash_password_produces_an_argon2_hash() -> None:
    hashed = hash_password("correct-password")

    assert hashed.startswith("$argon2")


def test_dummy_password_hash_is_argon2() -> None:
    """DUMMY_PASSWORD_HASH stands in for a real account's hash on the
    "no such user" login path, so it has to be verified with the same
    primary algorithm (Argon2) as an actual account -- otherwise an
    unknown-email request and a real-account wrong-password request
    are timed against different algorithms, reopening the timing
    side-channel this dummy hash exists to close."""
    assert DUMMY_PASSWORD_HASH.startswith("$argon2")


def test_verify_password_accepts_correct_password() -> None:
    hashed = hash_password("correct-password")

    assert verify_password("correct-password", hashed) is True


def test_verify_password_rejects_wrong_password() -> None:
    hashed = hash_password("correct-password")

    assert verify_password("wrong-password", hashed) is False


def test_verify_and_upgrade_password_leaves_argon2_hash_unchanged() -> None:
    hashed = hash_password("correct-password")

    valid, upgraded = verify_and_upgrade_password("correct-password", hashed)

    assert valid is True
    assert upgraded is None


def test_verify_and_upgrade_password_upgrades_legacy_bcrypt_hash() -> None:
    """A password hashed under the old passlib/bcrypt scheme must still
    verify, and the presented hash should come back re-hashed under the
    now-preferred Argon2 scheme so the caller (login) can persist it."""
    valid, upgraded = verify_and_upgrade_password(
        "correct-password", LEGACY_BCRYPT_HASH
    )

    assert valid is True
    assert upgraded is not None
    assert upgraded.startswith("$argon2")
    # And the freshly-upgraded hash verifies the same password.
    assert verify_password("correct-password", upgraded) is True


def test_verify_and_upgrade_password_rejects_wrong_password_for_legacy_hash() -> None:
    valid, upgraded = verify_and_upgrade_password("wrong-password", LEGACY_BCRYPT_HASH)

    assert valid is False
    assert upgraded is None


def test_create_access_token_carries_kid_header() -> None:
    token = create_access_token("user-1", ["read"])

    header = jwt.get_unverified_header(token)

    assert header["kid"] == settings.JWT_KID


def test_create_access_token_carries_expected_audience() -> None:
    token = create_access_token("user-1", ["read"])

    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience=settings.JWT_AUDIENCE,
    )

    assert payload["aud"] == settings.JWT_AUDIENCE
    assert payload["sub"] == "user-1"
    assert payload["scopes"] == ["read"]


def test_create_access_token_rejects_decode_with_wrong_audience() -> None:
    token = create_access_token("user-1", ["read"])

    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience="some-other-audience",
        )
