import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from kalekit.auth.dependencies import _decode_access_token, _signing_key_for_kid
from kalekit.config import settings


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# Maps the HMAC-SHA-2 `alg` values this helper knows how to sign for to
# their hashlib constructor -- keeps the raw-header helper below in sync
# with whatever settings.JWT_ALGORITHM actually is, instead of a
# hardcoded hashlib.sha256 that would silently make the signature (and
# thus the test) wrong if the app's configured algorithm ever changed.
_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _make_token_with_raw_header(header: dict[str, Any], key: str) -> str:
    """Hand-assemble a JWT rather than going through jwt.encode(), which
    (reasonably) refuses to emit a non-string `kid` itself. An attacker
    isn't bound by PyJWT's encode-side validation though -- they can put
    whatever JSON they like in the header -- so this is what actually
    exercises `_decode_access_token`'s handling of a malformed `kid`
    from the *unverified* header.
    """
    alg = header.get("alg", settings.JWT_ALGORITHM)
    assert alg in _HMAC_ALGORITHMS, (
        f"_make_token_with_raw_header only knows how to sign for "
        f"{sorted(_HMAC_ALGORITHMS)}, got {alg!r} -- extend _HMAC_ALGORITHMS "
        f"if settings.JWT_ALGORITHM has moved to a new scheme."
    )
    digestmod = _HMAC_ALGORITHMS[alg]

    payload = {
        "sub": "user-1",
        "jti": "jti-1",
        "type": "access",
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
        "aud": settings.JWT_AUDIENCE,
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = hmac.new(key.encode(), signing_input.encode(), digestmod).digest()
    return signing_input + "." + _b64url(signature)


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _make_token(
    *,
    key: str = settings.JWT_SECRET_KEY,
    kid: Any = settings.JWT_KID,
    algorithm: str = settings.JWT_ALGORITHM,
    aud: str | list[str] | None = settings.JWT_AUDIENCE,
    exp_delta: timedelta = timedelta(minutes=15),
    token_type: str = "access",
) -> str:
    payload = {
        "sub": "user-1",
        "jti": "jti-1",
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


@pytest.mark.parametrize("malformed_kid", [["not", "a", "string"], {"a": 1}, 123, ""])
def test_decode_rejects_token_with_non_string_kid(malformed_kid: object) -> None:
    """`kid` comes from the token's *unverified* header, so it's
    attacker-controlled JSON of any shape -- a list or dict here must
    be rejected cleanly (401), not raise an unhandled TypeError from
    treating it as a dict key (which would surface as a 500).

    Built by hand (not via `_make_token`/`jwt.encode`) because PyJWT's
    own encode() already refuses a non-string `kid` -- an attacker
    crafting the token bytes directly isn't bound by that.
    """
    token = _make_token_with_raw_header(
        {"alg": settings.JWT_ALGORITHM, "typ": "JWT", "kid": malformed_kid},
        settings.JWT_SECRET_KEY,
    )

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401


@pytest.mark.parametrize("malformed_kid", [["not", "a", "string"], {"a": 1}, 123, ""])
def test_signing_key_for_kid_returns_none_for_non_string_kid(
    malformed_kid: object,
) -> None:
    assert _signing_key_for_kid(malformed_kid) is None


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


def test_decode_rejects_wrong_token_type() -> None:
    token = _make_token(token_type="refresh")

    with pytest.raises(HTTPException) as exc_info:
        _decode_access_token(_credentials(token))

    assert exc_info.value.status_code == 401
