"""A fresh login works right after logout-all, password reset and
change-password (#229).

These endpoints used to set a user-wide `blocked_user:<id>` Redis key
that `get_current_user` applied to every token of the user, including
tokens from a login made after the action, until the key expired. The
`token_version` cut-off (#195) already rejects exactly the older tokens,
so the user-wide key is gone. These tests run with Redis available; the
Redis-down cases for the older tokens are in test_token_version_cutoff.py.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import get_redis
from kalekit.auth.repository import create_password_reset_token, find_user_by_email
from kalekit.auth.service import (
    generate_verification_token,
    hash_verification_token,
    password_reset_token_expiry,
)
from tests.auth.test_redis_revocation_guards import _login

_OLD = "old-password123"
_NEW = "new-password456"


async def _me_status(client: AsyncClient, auth_header, token: str) -> int:
    response = await client.get("/v1/auth/me", headers=auth_header(token))
    return response.status_code


@pytest.mark.asyncio(loop_scope="session")
async def test_fresh_login_works_right_after_logout_all(
    client: AsyncClient, register, auth_header
) -> None:
    email = "fresh-after-logout-all@example.com"
    await register(email, _OLD)
    old = await _login(client, email, _OLD)

    response = await client.post(
        "/v1/auth/logout-all", headers=auth_header(old["access_token"])
    )
    assert response.status_code == 204
    fresh = await _login(client, email, _OLD)

    assert await _me_status(client, auth_header, old["access_token"]) == 401
    assert await _me_status(client, auth_header, fresh["access_token"]) == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_fresh_login_works_right_after_password_reset(
    client: AsyncClient, register, auth_header, session: AsyncSession
) -> None:
    email = "fresh-after-reset@example.com"
    await register(email, _OLD)
    old = await _login(client, email, _OLD)
    user = await find_user_by_email(session, email)
    assert user is not None
    raw_token = generate_verification_token()
    await create_password_reset_token(
        session,
        user_id=user.id,
        token_hash=hash_verification_token(raw_token),
        expires_at=password_reset_token_expiry(),
    )

    response = await client.post(
        "/v1/auth/password/reset", json={"token": raw_token, "new_password": _NEW}
    )
    assert response.status_code == 200
    fresh = await _login(client, email, _NEW)

    assert await _me_status(client, auth_header, old["access_token"]) == 401
    assert await _me_status(client, auth_header, fresh["access_token"]) == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_fresh_login_works_right_after_change_password(
    client: AsyncClient, register, auth_header
) -> None:
    email = "fresh-after-change-pw@example.com"
    await register(email, _OLD)
    old = await _login(client, email, _OLD)

    response = await client.post(
        "/v1/auth/change-password",
        headers=auth_header(old["access_token"]),
        json={"current_password": _OLD, "new_password": _NEW},
    )
    assert response.status_code == 200
    fresh = await _login(client, email, _NEW)

    assert await _me_status(client, auth_header, old["access_token"]) == 401
    assert await _me_status(client, auth_header, fresh["access_token"]) == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_the_three_endpoints_set_no_user_wide_block_key(
    client: AsyncClient, register, auth_header, session: AsyncSession
) -> None:
    email = "no-user-key@example.com"
    await register(email, _OLD)
    first = await _login(client, email, _OLD)
    user = await find_user_by_email(session, email)
    assert user is not None
    r = await get_redis()

    await client.post(
        "/v1/auth/change-password",
        headers=auth_header(first["access_token"]),
        json={"current_password": _OLD, "new_password": _NEW},
    )
    assert await r.exists(f"blocked_user:{user.id}") == 0

    second = await _login(client, email, _NEW)
    await client.post(
        "/v1/auth/logout-all", headers=auth_header(second["access_token"])
    )
    assert await r.exists(f"blocked_user:{user.id}") == 0
