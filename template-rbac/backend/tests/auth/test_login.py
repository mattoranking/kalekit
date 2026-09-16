import pytest
from httpx import AsyncClient

import kalekit.auth.endpoints as auth_endpoints


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


@pytest.mark.asyncio(loop_scope="session")
async def test_unknown_email_and_wrong_password_return_identical_body(
    client: AsyncClient, register
) -> None:
    """Both failure paths must be indistinguishable to the caller, since
    that's the actual fix for the timing leak: an attacker probing for
    valid emails should see the same status and body either way.
    """
    await register("real-user@example.com", "correct-password")

    unknown_email_response = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.com", "password": "whatever"},
    )
    wrong_password_response = await client.post(
        "/v1/auth/login",
        json={"email": "real-user@example.com", "password": "wrong-password"},
    )

    assert unknown_email_response.status_code == wrong_password_response.status_code
    assert unknown_email_response.json() == wrong_password_response.json()


@pytest.mark.asyncio(loop_scope="session")
async def test_unknown_email_still_performs_password_verification(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point of the fix: an unknown email must not let the
    endpoint skip the (slow, by design) hash verification. Assert the
    verification function actually runs, rather than being short-circuited
    away because no user was found.
    """
    calls: list[tuple[str, str]] = []
    real_verify_password = auth_endpoints.verify_password

    def _spy_verify_password(plain: str, hashed: str) -> bool:
        calls.append((plain, hashed))
        return real_verify_password(plain, hashed)

    monkeypatch.setattr(auth_endpoints, "verify_password", _spy_verify_password)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.com", "password": "whatever"},
    )

    assert response.status_code == 401
    assert len(calls) == 1
    plain, hashed = calls[0]
    assert plain == "whatever"
    assert hashed == auth_endpoints.DUMMY_PASSWORD_HASH
