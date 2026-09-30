"""A 422 must not echo the submitted password back (#159).

FastAPI's default 422 body carries each error's `input`; for a password
rejected by the length rule (#123) that is the password itself. For an
error on the body as a whole (a missing field) `input` is the entire
request body, so it would also carry the other password fields.
"""

import pytest
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import (
    create_password_reset_token,
    find_user_by_email,
)
from kalekit.auth.service import (
    generate_verification_token,
    hash_verification_token,
    password_reset_token_expiry,
)

TOO_SHORT = "Zq9-short"  # 9 characters, below the 12 minimum
TOO_LONG = "Zq9-long-" * 15  # 135 characters, above the 128 maximum
CURRENT = "password12345"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _assert_clean(response: Response, secret: str, field: str) -> None:
    assert response.status_code == 422
    assert secret not in response.text
    errors = response.json()["detail"]
    assert any(field in e["loc"] for e in errors)
    for e in errors:
        assert "input" not in e
        assert e["msg"]
        assert e["type"]


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("password", [TOO_SHORT, TOO_LONG])
async def test_register_422_does_not_echo_password(register, password: str) -> None:
    response = await register("echo-reg@example.com", password)

    _assert_clean(response, password, "password")
    assert "between 12 and 128 characters" in response.text


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("password", [TOO_SHORT, TOO_LONG])
async def test_change_password_422_does_not_echo_password(
    client: AsyncClient, register, login, password: str
) -> None:
    await register("echo-chg@example.com", CURRENT)
    token = await login("echo-chg@example.com", CURRENT)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(token),
        json={"current_password": CURRENT, "new_password": password},
    )

    _assert_clean(response, password, "new_password")
    assert CURRENT not in response.text


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_body_level_422_does_not_echo_current_password(
    client: AsyncClient, register, login
) -> None:
    await register("echo-chg-body@example.com", CURRENT)
    token = await login("echo-chg-body@example.com", CURRENT)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(token),
        json={"current_password": CURRENT},
    )

    _assert_clean(response, CURRENT, "new_password")


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("password", [TOO_SHORT, TOO_LONG])
async def test_reset_password_422_does_not_echo_password(
    client: AsyncClient, register, session: AsyncSession, password: str
) -> None:
    email = "echo-rst@example.com"
    await register(email)
    user = await find_user_by_email(session, email)
    assert user is not None
    raw = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw),
        expires_at=password_reset_token_expiry(),
    )

    response = await client.post(
        "/v1/auth/password/reset",
        json={"token": raw, "new_password": password},
    )

    _assert_clean(response, password, "new_password")
    assert raw not in response.text


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_body_level_422_does_not_echo_token(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/v1/auth/password/reset", json={"token": "tok-secret-value-123"}
    )

    _assert_clean(response, "tok-secret-value-123", "new_password")


@pytest.mark.asyncio(loop_scope="session")
async def test_non_validation_errors_are_unchanged(client: AsyncClient) -> None:
    missing = await client.get("/v1/no-such-route")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Not Found"}

    unauth = await client.post(
        "/v1/auth/change-password",
        json={"current_password": CURRENT, "new_password": "n" * 20},
    )
    assert unauth.status_code in (401, 403)
    assert set(unauth.json()) == {"detail"}
    assert isinstance(unauth.json()["detail"], str)
