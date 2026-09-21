from datetime import datetime, timedelta, timezone

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.auth.service import create_access_token
from kalekit.config import settings


def _access_token_with_bad_sid(user_id: str) -> str:
    """A hand-built access token with a malformed `sid` claim -- the
    kind create_access_token would never itself produce, but the token
    is attacker-influenceable in principle, so the endpoint has to
    survive a bad one rather than crash on it."""
    payload = {
        "sub": user_id,
        "jti": "bad-sid-test-jti",
        "scopes": [],
        "type": "access",
        "sid": "not-a-uuid",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        "aud": "web",
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
        headers={"kid": settings.JWT_KID},
    )


async def _login_pair(
    client: AsyncClient, email: str, password: str = "password12345"
) -> tuple[str, str]:
    """Register + login, returning (access_token, refresh_token)."""
    await client.post(
        "/v1/auth/register",
        json={"email": email, "password": password},
    )
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_rejects_wrong_current_password(
    client: AsyncClient,
) -> None:
    access_token, _ = await _login_pair(client, "change-pw-wrong@example.com")

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "not-it", "new_password": "newpassword456"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_allows_login_with_the_new_password(
    client: AsyncClient,
) -> None:
    email = "change-pw-login@example.com"
    access_token, _ = await _login_pair(client, email)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(access_token),
        json={"current_password": "password12345", "new_password": "newpassword456"},
    )
    assert response.status_code == 200

    old_password_login = await client.post(
        "/v1/auth/login", json={"email": email, "password": "password12345"}
    )
    assert old_password_login.status_code == 401

    new_password_login = await client.post(
        "/v1/auth/login", json={"email": email, "password": "newpassword456"}
    )
    assert new_password_login.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_revokes_other_sessions_but_keeps_the_current_one(
    client: AsyncClient,
) -> None:
    email = "change-pw-sessions@example.com"
    current_access, current_refresh = await _login_pair(client, email)
    other_access, other_refresh = await _login_pair(client, email)

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(current_access),
        json={"current_password": "password12345", "new_password": "newpassword456"},
    )
    assert response.status_code == 200

    # The session the change was made from keeps working.
    current_refresh_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": current_refresh}
    )
    assert current_refresh_response.status_code == 200

    still_ok = await client.get("/v1/auth/me", headers=_auth(current_access))
    assert still_ok.status_code == 200

    # The other session is dead: its refresh token is revoked...
    other_refresh_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": other_refresh}
    )
    assert other_refresh_response.status_code == 401

    # ...and its still-unexpired access token stops working immediately,
    # rather than lingering until ACCESS_TOKEN_EXPIRE_MINUTES passes.
    other_me_response = await client.get("/v1/auth/me", headers=_auth(other_access))
    assert other_me_response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_requires_authentication(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/change-password",
        json={"current_password": "password12345", "new_password": "newpassword456"},
    )
    assert response.status_code in (401, 403)


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_without_a_session_id_requires_reauth_not_500(
    client: AsyncClient, session: AsyncSession
) -> None:
    """Some access tokens carry no `sid` claim (minted outside
    login/refresh/OAuth, or by older code). Since #16, change-password
    is gated by `require_recent_auth`, which needs a real session row
    to read a recency proof from -- a sidless token has none, so it
    fails closed with `reauth_required` rather than an unguarded
    uuid.UUID() parse turning it into an unhandled 500, and rather than
    the pre-#16 behavior of proceeding and blocking every access token
    the user holds (change_password's own keep_family_id=None fallback,
    now unreachable through this endpoint precisely because
    require_recent_auth rejects the request before that logic runs)."""
    email = "change-pw-no-sid@example.com"
    await _login_pair(client, email)

    user = await find_user_by_email(session, email)
    assert user is not None
    sidless_token = create_access_token(str(user.id), [])

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(sidless_token),
        json={"current_password": "password12345", "new_password": "newpassword456"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "reauth_required"


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_with_a_malformed_sid_fails_closed_not_500(
    client: AsyncClient, session: AsyncSession
) -> None:
    """`sid` is attacker-influenceable in principle -- a malformed
    value must be treated the same as no session id: `require_recent_auth`
    (#16) fails closed with `reauth_required` instead of an unguarded
    uuid.UUID() parse turning it into an unhandled 500."""
    email = "change-pw-bad-sid@example.com"
    await _login_pair(client, email)

    user = await find_user_by_email(session, email)
    assert user is not None
    bad_sid_token = _access_token_with_bad_sid(str(user.id))

    response = await client.post(
        "/v1/auth/change-password",
        headers=_auth(bad_sid_token),
        json={"current_password": "password12345", "new_password": "newpassword456"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "reauth_required"
