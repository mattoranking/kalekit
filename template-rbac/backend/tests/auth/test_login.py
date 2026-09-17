import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import kalekit.auth.endpoints as auth_endpoints
from kalekit.auth.repository import find_user_by_email
from kalekit.config import settings

LEGACY_BCRYPT_HASH = "$2b$12$fVcEWj4wDMGN/yfRQAywQOHPaZ3rPZ40inFuNlnwkGuym1KhnL1mu"


@pytest.mark.asyncio(loop_scope="session")
async def test_login_succeeds_with_correct_password(register, login) -> None:
    await register("user@example.com", "correct-password")

    token = await login("user@example.com", "correct-password")

    assert token


@pytest.mark.asyncio(loop_scope="session")
async def test_login_upgrades_a_legacy_bcrypt_hash_to_argon2(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    """Accounts created under the old passlib/bcrypt setup must keep
    working after the pwdlib migration, and get quietly moved onto
    Argon2 the next time they log in -- no forced password reset."""
    email = "legacy-hash@example.com"
    await register(email, "correct-password")

    user = await find_user_by_email(session, email)
    assert user is not None
    # Simulate a pre-migration account: a stored bcrypt hash rather than
    # the Argon2 hash `register` would have produced today.
    user.password_hash = LEGACY_BCRYPT_HASH
    await session.flush()

    response = await client.post(
        "/v1/auth/login",
        json={"email": email, "password": "correct-password"},
    )
    assert response.status_code == 200

    upgraded_user = await find_user_by_email(session, email)
    assert upgraded_user is not None
    assert upgraded_user.password_hash.startswith("$argon2")

    # And the upgraded hash still logs the user in on a subsequent request.
    second_response = await client.post(
        "/v1/auth/login",
        json={"email": email, "password": "correct-password"},
    )
    assert second_response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_login_rejected_for_unverified_email_does_not_upgrade_hash(
    client: AsyncClient,
    register,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A login that's ultimately rejected (here: unverified email, with
    REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN on) must not have side
    effects -- in particular it must not silently upgrade a legacy
    bcrypt hash to Argon2 before the verification check runs. The
    upgrade should only ever happen alongside an actual, successful
    login.
    """
    monkeypatch.setattr(settings, "REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN", True)

    email = "unverified-legacy-hash@example.com"
    await register(email, "correct-password")

    user = await find_user_by_email(session, email)
    assert user is not None
    assert user.email_verified is False
    user.password_hash = LEGACY_BCRYPT_HASH
    await session.flush()

    response = await client.post(
        "/v1/auth/login",
        json={"email": email, "password": "correct-password"},
    )
    assert response.status_code == 403

    unchanged_user = await find_user_by_email(session, email)
    assert unchanged_user is not None
    assert unchanged_user.password_hash == LEGACY_BCRYPT_HASH


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
    real_verify_and_upgrade_password = auth_endpoints.verify_and_upgrade_password

    def _spy_verify_and_upgrade_password(
        plain: str, hashed: str
    ) -> tuple[bool, str | None]:
        calls.append((plain, hashed))
        return real_verify_and_upgrade_password(plain, hashed)

    monkeypatch.setattr(
        auth_endpoints,
        "verify_and_upgrade_password",
        _spy_verify_and_upgrade_password,
    )

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
