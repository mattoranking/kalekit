from collections.abc import Coroutine
from typing import Callable

import pytest
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

import kalekit.auth.endpoints as auth_endpoints
from kalekit.auth.service import DUMMY_PASSWORD_HASH, password_hash
from kalekit.oauth.repository import find_or_create_oauth_user


@pytest.mark.asyncio(loop_scope="session")
async def test_login_against_oauth_only_account_returns_401_not_500(
    session: AsyncSession,
    client: AsyncClient,
) -> None:
    """OAuth-only users are created with password_hash=None. A password
    login against their email must return a clean 401. Argon2 hash
    verification raises on a missing hash, so the endpoint has to
    reject it before calling the hasher."""
    await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="oauth-only-1",
        account_email="oauth-only@example.com",
    )

    response = await client.post(
        "/v1/auth/login",
        json={"email": "oauth-only@example.com", "password": "any-password"},
    )

    assert response.status_code == 401


def _spy_verify(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    real = auth_endpoints.verify_password

    def _spy(plain: str, hashed: str) -> bool:
        calls.append((plain, hashed))
        return real(plain, hashed)

    monkeypatch.setattr(auth_endpoints, "verify_password", _spy)
    return calls


@pytest.mark.asyncio(loop_scope="session")
async def test_unknown_email_runs_one_verify_against_dummy_hash(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _spy_verify(monkeypatch)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.com", "password": "password12345"},
    )

    assert response.status_code == 401
    assert calls == [("password12345", DUMMY_PASSWORD_HASH)]


@pytest.mark.asyncio(loop_scope="session")
async def test_wrong_password_runs_one_verify(
    register: Callable[..., Coroutine[None, None, Response]],
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await register("carol@example.com", password="password12345")
    calls = _spy_verify(monkeypatch)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "carol@example.com", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert len(calls) == 1
    assert calls[0][0] == "wrong-password"
    assert calls[0][1] != DUMMY_PASSWORD_HASH


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_only_account_runs_one_verify_against_dummy_hash(
    session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="oauth-only-timing",
        account_email="oauth-timing@example.com",
    )
    calls = _spy_verify(monkeypatch)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "oauth-timing@example.com", "password": "any-password"},
    )

    assert response.status_code == 401
    assert calls == [("any-password", DUMMY_PASSWORD_HASH)]


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_only_account_is_refused_even_if_dummy_verify_succeeds(
    session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dummy hash's password is unknowable, but the guard must not
    depend on that: an OAuth-only account (no password_hash) never logs
    in by password, even if the verifier reports a match."""
    await find_or_create_oauth_user(
        session,
        platform="github",
        account_id="oauth-only-guard",
        account_email="oauth-guard@example.com",
    )
    monkeypatch.setattr(auth_endpoints, "verify_password", lambda plain, hashed: True)

    response = await client.post(
        "/v1/auth/login",
        json={"email": "oauth-guard@example.com", "password": "any-password"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_unknown_email_and_wrong_password_return_identical_body(
    register: Callable[..., Coroutine[None, None, Response]],
    client: AsyncClient,
) -> None:
    await register("dave@example.com", password="password12345")

    unknown = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.com", "password": "whatever-pass"},
    )
    wrong = await client.post(
        "/v1/auth/login",
        json={"email": "dave@example.com", "password": "wrong-password"},
    )

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_dummy_hash_is_argon2_with_current_hasher_parameters() -> None:
    """The dummy verify costs the same as a real one only while the
    constant keeps the parameters Argon2Hasher() produces today."""
    assert not password_hash.current_hasher.check_needs_rehash(DUMMY_PASSWORD_HASH)
    assert DUMMY_PASSWORD_HASH.startswith("$argon2id$")
