"""The password length rule (#123): one shared rule on register; login
enforces only the maximum, cheaply, with the same uniform 401 as a wrong
password. (This template has no change-password or reset endpoint.)"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import kalekit.auth.service as auth_service
from kalekit.auth.repository import create_user
from kalekit.config import Settings, settings

MIN = 12
MAX = 128


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


@pytest.fixture
def hash_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Records every bcrypt verification (the real one still runs)."""
    calls: list[str] = []
    real = auth_service.pwd_context.verify

    def _spy(secret: str, hashed: str, *args, **kwargs) -> bool:
        calls.append(secret)
        return real(secret, hashed, *args, **kwargs)

    monkeypatch.setattr(auth_service.pwd_context, "verify", _spy)
    return calls


@pytest.mark.asyncio(loop_scope="session")
async def test_login_with_oversized_password_matches_wrong_password_and_skips_hash(
    client: AsyncClient, register, hash_spy: list[str]
) -> None:
    await register("login-big@example.com")
    wrong = await client.post(
        "/v1/auth/login",
        json={"email": "login-big@example.com", "password": "not-the-password"},
    )
    assert hash_spy  # the wrong-password path does run the hash
    hash_spy.clear()

    oversized = await client.post(
        "/v1/auth/login",
        json={"email": "login-big@example.com", "password": "a" * (MAX + 1)},
    )
    huge = await client.post(
        "/v1/auth/login",
        json={"email": "login-big@example.com", "password": "a" * 1_000_000},
    )

    assert wrong.status_code == oversized.status_code == huge.status_code == 401
    assert wrong.json() == oversized.json() == huge.json()
    assert hash_spy == []


@pytest.mark.asyncio(loop_scope="session")
async def test_login_accepts_a_password_of_exactly_the_max(
    client: AsyncClient, register, hash_spy: list[str]
) -> None:
    await register("login-max@example.com", "a" * MAX)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "login-max@example.com", "password": "a" * MAX},
    )

    assert response.status_code == 200
    assert hash_spy == ["a" * MAX]


@pytest.mark.asyncio(loop_scope="session")
async def test_login_still_works_with_a_short_legacy_password(
    client: AsyncClient, session: AsyncSession
) -> None:
    """Accounts created before the rule existed keep signing in."""
    await create_user(session, "legacy-short@example.com", "short")

    response = await client.post(
        "/v1/auth/login",
        json={"email": "legacy-short@example.com", "password": "short"},
    )

    assert response.status_code == 200
