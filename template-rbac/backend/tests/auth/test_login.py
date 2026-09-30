import jwt
import pytest
from httpx import AsyncClient

import kalekit.auth.endpoints as auth_endpoints
from kalekit.config import settings
from kalekit.oauth.repository import find_or_create_oauth_user


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


@pytest.mark.asyncio(loop_scope="session")
async def test_login_without_a_client_defaults_to_web(
    client: AsyncClient, register
) -> None:
    await register("no-client@example.com", "correct-password")

    response = await client.post(
        "/v1/auth/login",
        json={"email": "no-client@example.com", "password": "correct-password"},
    )
    assert response.status_code == 200

    payload = jwt.decode(
        response.json()["access_token"],
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience="web",
    )
    assert payload["aud"] == "web"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("client_type", ["web", "mobile", "admin"])
async def test_login_stamps_the_requested_client_onto_the_access_token(
    client: AsyncClient, register, client_type: str
) -> None:
    email = f"client-{client_type}@example.com"
    await register(email, "correct-password")

    response = await client.post(
        "/v1/auth/login",
        json={
            "email": email,
            "password": "correct-password",
            "client": client_type,
        },
    )
    assert response.status_code == 200

    payload = jwt.decode(
        response.json()["access_token"],
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience=client_type,
    )
    assert payload["aud"] == client_type


@pytest.mark.asyncio(loop_scope="session")
async def test_login_rejects_an_unknown_client(client: AsyncClient, register) -> None:
    await register("bad-client@example.com", "correct-password")

    response = await client.post(
        "/v1/auth/login",
        json={
            "email": "bad-client@example.com",
            "password": "correct-password",
            "client": "not-a-real-client",
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_only_account_is_refused_even_if_verifier_returns_true(
    client: AsyncClient,
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal of an OAuth-only account (password_hash None) must not
    rest on nobody knowing the dummy hash's password: if the verifier
    ever returned True, the account must still be refused."""
    await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="oauth-only-guard",
        account_email="oauth-guard@example.com",
    )
    monkeypatch.setattr(auth_endpoints, "verify_password", lambda plain, hashed: True)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "oauth-guard@example.com", "password": "anything-at-all"},
    )

    assert response.status_code == 401
