"""The password length rule (#123): one shared rule on register,
change-password and reset-password; login enforces only the maximum,
cheaply, with the same uniform 401 as a wrong password."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import kalekit.auth.service as auth_service
from kalekit.auth.repository import (
    create_password_reset_token,
    create_user,
    find_user_by_email,
)
from kalekit.auth.service import (
    generate_verification_token,
    hash_verification_token,
    password_reset_token_expiry,
)
from kalekit.config import Settings, settings

MIN = 12
MAX = 128
NEW_OK = "n" * 20


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_defaults_are_12_and_128() -> None:
    assert settings.PASSWORD_MIN_LENGTH == MIN
    assert settings.PASSWORD_MAX_LENGTH == MAX


def test_min_above_max_is_rejected() -> None:
    with pytest.raises(ValueError, match="PASSWORD_MIN_LENGTH"):
        Settings(PASSWORD_MIN_LENGTH=20, PASSWORD_MAX_LENGTH=10)


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("length", [1, MIN - 1, MAX + 1, 100_000])
async def test_register_rejects_out_of_range_length(register, length: int) -> None:
    response = await register(f"reg-bad-{length}@example.com", "a" * length)

    assert response.status_code == 422
    assert f"between {MIN} and {MAX} characters" in response.text


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("length", [MIN, MAX])
async def test_register_accepts_exact_bounds(register, login, length: int) -> None:
    email = f"reg-ok-{length}@example.com"

    response = await register(email, "a" * length)

    assert response.status_code == 201
    assert await login(email, "a" * length)


@pytest.mark.asyncio(loop_scope="session")
async def test_length_is_counted_in_characters_not_bytes(register) -> None:
    # 12 characters, 24 bytes in UTF-8.
    response = await register("reg-chars@example.com", "é" * MIN)
    assert response.status_code == 201

    # 128 multibyte characters is still at the limit.
    response = await register("reg-chars-max@example.com", "é" * MAX)
    assert response.status_code == 201


@pytest.mark.asyncio(loop_scope="session")
async def test_bounds_come_from_settings(
    register, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "PASSWORD_MIN_LENGTH", 4)
    monkeypatch.setattr(settings, "PASSWORD_MAX_LENGTH", 6)

    assert (await register("cfg-3@example.com", "a" * 3)).status_code == 422
    assert (await register("cfg-4@example.com", "a" * 4)).status_code == 201
    assert (await register("cfg-6@example.com", "a" * 6)).status_code == 201
    assert (await register("cfg-7@example.com", "a" * 7)).status_code == 422


async def _session_for(client: AsyncClient, register, email: str) -> str:
    assert (await register(email)).status_code == 201
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "password12345"}
    )
    return response.json()["access_token"]


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("length", [MIN - 1, MAX + 1])
async def test_change_password_rejects_out_of_range_new_password(
    client: AsyncClient, register, length: int
) -> None:
    token = await _session_for(client, register, f"chg-bad-{length}@example.com")

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(token),
        json={"current_password": "password12345", "new_password": "a" * length},
    )

    assert response.status_code == 422
    assert f"between {MIN} and {MAX} characters" in response.text


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("length", [MIN, MAX])
async def test_change_password_accepts_exact_bounds(
    client: AsyncClient, register, login, length: int
) -> None:
    email = f"chg-ok-{length}@example.com"
    token = await _session_for(client, register, email)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(token),
        json={"current_password": "password12345", "new_password": "b" * length},
    )

    assert response.status_code == 200
    assert await login(email, "b" * length)


async def _reset_token(session: AsyncSession, email: str) -> str:
    user = await find_user_by_email(session, email)
    assert user is not None
    raw = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw),
        expires_at=password_reset_token_expiry(),
    )
    return raw


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("length", [MIN - 1, MAX + 1])
async def test_reset_password_rejects_out_of_range_length(
    client: AsyncClient, register, session: AsyncSession, length: int
) -> None:
    email = f"rst-bad-{length}@example.com"
    await register(email)
    token = await _reset_token(session, email)

    response = await client.post(
        "/v1/auth/password/reset",
        json={"token": token, "new_password": "a" * length},
    )

    assert response.status_code == 422
    assert f"between {MIN} and {MAX} characters" in response.text


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("length", [MIN, MAX])
async def test_reset_password_accepts_exact_bounds(
    client: AsyncClient, register, login, session: AsyncSession, length: int
) -> None:
    email = f"rst-ok-{length}@example.com"
    await register(email)
    token = await _reset_token(session, email)

    response = await client.post(
        "/v1/auth/password/reset",
        json={"token": token, "new_password": "c" * length},
    )

    assert response.status_code == 200
    assert await login(email, "c" * length)


@pytest.fixture
def argon2_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Records every Argon2 verification (the real one still runs)."""
    calls: list[str] = []
    real = auth_service.password_hash.verify

    def _spy(password: str, hashed: str) -> bool:
        calls.append(password)
        return real(password, hashed)

    monkeypatch.setattr(auth_service.password_hash, "verify", _spy)
    return calls


@pytest.mark.asyncio(loop_scope="session")
async def test_login_with_oversized_password_matches_wrong_password_and_skips_argon2(
    client: AsyncClient, register, argon2_spy: list[str]
) -> None:
    await register("login-big@example.com")
    wrong = await client.post(
        "/v1/auth/login",
        json={"email": "login-big@example.com", "password": "not-the-password"},
    )
    argon2_spy.clear()

    oversized = await client.post(
        "/v1/auth/login",
        json={"email": "login-big@example.com", "password": "a" * (MAX + 1)},
    )
    unknown = await client.post(
        "/v1/auth/login",
        json={"email": "nobody-big@example.com", "password": "a" * 1_000_000},
    )

    assert wrong.status_code == oversized.status_code == unknown.status_code == 401
    assert wrong.json() == oversized.json() == unknown.json()
    assert argon2_spy == []


@pytest.mark.asyncio(loop_scope="session")
async def test_login_accepts_a_password_of_exactly_the_max(
    client: AsyncClient, register, argon2_spy: list[str]
) -> None:
    await register("login-max@example.com", "a" * MAX)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "login-max@example.com", "password": "a" * MAX},
    )

    assert response.status_code == 200
    assert argon2_spy == ["a" * MAX]


@pytest.mark.asyncio(loop_scope="session")
async def test_login_still_works_with_a_short_legacy_password(
    client: AsyncClient, session: AsyncSession
) -> None:
    """Accounts created before the rule existed keep signing in, and
    can then change to a compliant password."""
    await create_user(session, "legacy-short@example.com", "short", email_verified=True)

    login = await client.post(
        "/v1/auth/login",
        json={"email": "legacy-short@example.com", "password": "short"},
    )
    assert login.status_code == 200

    change = await client.post(
        "/v1/auth/change-password",
        headers=_auth(login.json()["access_token"]),
        json={"current_password": "short", "new_password": NEW_OK},
    )
    assert change.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_with_oversized_current_password_is_401_without_argon2(
    client: AsyncClient, register, argon2_spy: list[str]
) -> None:
    token = await _session_for(client, register, "chg-big-current@example.com")
    argon2_spy.clear()

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(token),
        json={"current_password": "a" * 500_000, "new_password": NEW_OK},
    )

    assert response.status_code == 401
    assert argon2_spy == []
