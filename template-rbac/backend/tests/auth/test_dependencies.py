from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from kalekit.auth.dependencies import _decode_access_token
from kalekit.config import settings


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _make_token(
    *,
    key: str = settings.JWT_SECRET_KEY,
    kid: str | None = settings.JWT_KID,
    algorithm: str = settings.JWT_ALGORITHM,
    aud: str | None = settings.JWT_AUDIENCE,
    exp_delta: timedelta = timedelta(minutes=15),
    token_type: str = "access",
) -> str:
    payload = {
        "sub": "user-1",
        "jti": "jti-1",
        "scopes": ["read"],
        "type": token_type,
        "exp": datetime.now(timezone.utc) + exp_delta,
    }
    if aud is not None:
        payload["aud"] = aud
    headers = {"kid": kid} if kid is not None else None
    return jwt.encode(payload, key, algorithm=algorithm, headers=headers)


def test_decode_accepts_a_validly_signed_current_token() -> None:
    token = _make_token()

    payload = _decode_access_token(_credentials(token))

    assert payload["sub"] == "user-1"


def test_decode_rejects_expired_token() -> None:
    token = _make_token(exp_delta=timedelta(minutes=-5))

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401


def test_decode_tolerates_small_clock_skew_within_leeway() -> None:
    """A token that expired a couple seconds ago should still pass,
    given JWT_LEEWAY_SECONDS -- this is what protects against a
    slightly-behind server clock spuriously rejecting fresh tokens."""
    token = _make_token(exp_delta=timedelta(seconds=-5))

    payload = _decode_access_token(_credentials(token))

    assert payload["sub"] == "user-1"


def test_decode_rejects_token_missing_audience_claim() -> None:
    token = _make_token(aud=None)

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401


def test_decode_rejects_token_with_wrong_audience() -> None:
    token = _make_token(aud="some-other-service")

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401


def test_decode_rejects_token_with_unknown_kid() -> None:
    token = _make_token(kid="not-a-real-key-id")

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401


def test_decode_rejects_token_missing_kid_header() -> None:
    token = _make_token(kid=None)

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401


def test_decode_accepts_token_signed_with_a_previous_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulates a secret rotation: a token signed under an old kid/key
    must still verify as long as that key is listed in
    JWT_PREVIOUS_KEYS, so rotating the secret doesn't instantly log
    every existing session out."""
    previous_key = "the-previous-signing-secret"
    token = _make_token(key=previous_key, kid="previous")

    monkeypatch.setattr(settings, "JWT_PREVIOUS_KEYS", {"previous": previous_key})

    payload = _decode_access_token(_credentials(token))

    assert payload["sub"] == "user-1"


def test_decode_rejects_token_signed_with_wrong_key_for_its_kid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token claiming a known kid but actually signed with a
    different key must be rejected -- the kid alone isn't proof, the
    signature still has to check out against the key it names."""
    token = _make_token(key="an-attacker-controlled-secret", kid="previous")

    monkeypatch.setattr(
        settings, "JWT_PREVIOUS_KEYS", {"previous": "the-real-previous-secret"}
    )

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401


def test_decode_rejects_unparseable_token() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials("not-a-jwt-at-all"))

    assert exc_info.value.status_code == 401


def test_decode_rejects_token_with_wrong_algorithm() -> None:
    """The algorithm list is pinned explicitly on decode (not trusted
    from the token's own `alg` header), which is what closes the
    classic JWT algorithm-confusion attack."""
    token = _make_token(algorithm="HS384")

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401
