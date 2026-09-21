from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient

from kalekit.auth.dependencies import get_current_jti
from kalekit.auth.service import create_access_token
from kalekit.config import settings


def _token(iss: str | None = settings.JWT_ISSUER) -> str:
    payload: dict[str, object] = {
        "sub": "00000000-0000-0000-0000-000000000001",
        "jti": "issuer-test-jti",
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    if iss is not None:
        payload["iss"] = iss
    return jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_create_access_token_carries_configured_issuer() -> None:
    token = create_access_token("user-1")

    claims = jwt.decode(token, options={"verify_signature": False})

    assert claims["iss"] == settings.JWT_ISSUER


@pytest.mark.parametrize("iss", [None, "some-other-deployment"])
@pytest.mark.asyncio(loop_scope="session")
async def test_get_current_user_rejects_missing_or_wrong_issuer(
    client: AsyncClient, auth_header, iss: str | None
) -> None:
    response = await client.get("/v1/auth/me", headers=auth_header(_token(iss)))

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"


@pytest.mark.parametrize("iss", [None, "some-other-deployment"])
@pytest.mark.asyncio(loop_scope="session")
async def test_get_current_jti_rejects_missing_or_wrong_issuer(
    iss: str | None,
) -> None:
    with pytest.raises(HTTPException) as exc_info:
        await get_current_jti(_credentials(_token(iss)))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"


@pytest.mark.asyncio(loop_scope="session")
async def test_get_current_jti_accepts_the_configured_issuer() -> None:
    assert await get_current_jti(_credentials(_token())) == "issuer-test-jti"


@pytest.mark.asyncio(loop_scope="session")
async def test_issuer_follows_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "JWT_ISSUER", "kalekit-staging")

    assert await get_current_jti(_credentials(_token("kalekit-staging"))) == (
        "issuer-test-jti"
    )
    with pytest.raises(HTTPException):
        await get_current_jti(_credentials(_token("kalekit")))


@pytest.mark.asyncio(loop_scope="session")
async def test_refreshed_access_token_carries_issuer_and_is_accepted(
    client: AsyncClient, register, auth_header
) -> None:
    """Clients recover from pre-`iss` tokens by refreshing: the token
    /auth/refresh returns must carry `iss` and authenticate."""
    await register("issuer-refresh@example.com")
    login = await client.post(
        "/v1/auth/login",
        json={"email": "issuer-refresh@example.com", "password": "password12345"},
    )
    assert login.status_code == 200, login.text

    refreshed = await client.post(
        "/v1/auth/refresh", json={"refresh_token": login.json()["refresh_token"]}
    )

    assert refreshed.status_code == 200
    access_token = refreshed.json()["access_token"]
    claims = jwt.decode(access_token, options={"verify_signature": False})
    assert claims["iss"] == settings.JWT_ISSUER
    me = await client.get("/v1/auth/me", headers=auth_header(access_token))
    assert me.status_code == 200
