import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from kalekit.auth.client_type import ClientType
from kalekit.auth.service import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    generate_refresh_token,
    hash_password,
    verify_password,
)
from kalekit.config import settings


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


def test_create_access_token_carries_kid_header() -> None:
    token = create_access_token("user-1", ["read"])

    header = jwt.get_unverified_header(token)

    assert header["kid"] == settings.JWT_KID


def test_create_access_token_carries_configured_issuer() -> None:
    token = create_access_token("user-1", ["read"])

    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience=ClientType.web.value,
    )

    assert payload["iss"] == settings.JWT_ISSUER


def test_create_access_token_defaults_to_web_audience() -> None:
    """No explicit client -- defaults to the web client, matching
    LoginRequest.client's default."""
    token = create_access_token("user-1", ["read"])

    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience=ClientType.web.value,
    )

    assert payload["aud"] == "web"
    assert payload["sub"] == "user-1"
    assert payload["scopes"] == ["read"]


@pytest.mark.parametrize("client_type", list(ClientType))
def test_create_access_token_carries_the_requested_client_as_audience(
    client_type: ClientType,
) -> None:
    """The `aud` claim is the client the token was minted for -- this
    is what lets require_admin_client tell an admin-client token apart
    from a web/mobile one that merely carries admin scopes. See #6."""
    token = create_access_token("user-1", ["read"], client=client_type)

    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience=client_type.value,
    )

    assert payload["aud"] == client_type.value


def test_create_access_token_rejects_decode_with_wrong_audience() -> None:
    token = create_access_token("user-1", ["read"], client=ClientType.web)

    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience="some-other-audience",
        )


@pytest.mark.parametrize(
    ("client_type", "expected_minutes"),
    [
        (ClientType.web, "ACCESS_TOKEN_EXPIRE_MINUTES_WEB"),
        (ClientType.mobile, "ACCESS_TOKEN_EXPIRE_MINUTES_MOBILE"),
        (ClientType.admin, "ACCESS_TOKEN_EXPIRE_MINUTES_ADMIN"),
    ],
)
def test_create_access_token_uses_the_clients_configured_lifetime(
    client_type: ClientType, expected_minutes: str
) -> None:
    """Each client has its own access token lifetime (admin's is
    shorter than web/mobile's by default -- see config.py)."""
    now = time.time()
    token = create_access_token("user-1", ["read"], client=client_type)

    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience=client_type.value,
    )

    expected_delta = getattr(settings, expected_minutes) * 60
    # No `iat` claim is minted, so compare `exp` against "now" (captured
    # just before minting) with generous slack instead of requiring an
    # exact issued-at timestamp.
    assert abs((payload["exp"] - now) - expected_delta) < 5


def test_generate_refresh_token_uses_the_clients_idle_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "SESSION_IDLE_TIMEOUT_MINUTES_ADMIN", 30)

    now = datetime.now(timezone.utc)
    _, expires_at = generate_refresh_token(ClientType.admin)

    expected = now + timedelta(minutes=30)
    assert abs((expires_at - expected).total_seconds()) < 5
