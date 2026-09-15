import pytest
from httpx import AsyncClient


@pytest.mark.asyncio(loop_scope="session")
async def test_login_succeeds_with_correct_password(register, login) -> None:
    await register("user@example.com", "correct-password")

    token = await login("user@example.com", "correct-password")

    assert token


@pytest.mark.asyncio(loop_scope="session")
async def test_login_fails_with_wrong_password(
    client: AsyncClient, register
) -> None:
    await register("user@example.com", "correct-password")

    response = await client.post(
        "/v1/auth/login",
        json={"email": "user@example.com", "password": "wrong-password"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_login_fails_for_unknown_email(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.com", "password": "whatever"},
    )

    assert response.status_code == 401
