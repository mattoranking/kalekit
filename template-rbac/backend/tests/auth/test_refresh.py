import pytest
from httpx import AsyncClient

from kalekit.config import settings


async def _login_pair(client: AsyncClient, email: str) -> tuple[str, str]:
    """Register + login, returning (access_token, refresh_token)."""
    await client.post(
        "/v1/auth/register",
        json={"email": email, "password": "password123"},
    )
    response = await client.post(
        "/v1/auth/login",
        json={"email": email, "password": "password123"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["access_token"], body["refresh_token"]


async def _refresh(client: AsyncClient, refresh_token: str):
    return await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_rotates_and_returns_a_new_pair(client: AsyncClient) -> None:
    _, refresh_token = await _login_pair(client, "rotate@example.com")

    response = await _refresh(client, refresh_token)

    assert response.status_code == 200
    body = response.json()
    assert body["refresh_token"] != refresh_token
    assert body["access_token"]


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_refresh_within_grace_window_returns_same_pair(
    client: AsyncClient,
) -> None:
    """Two requests racing in with the same about-to-be-rotated token
    (e.g. two serverless BFF instances) must both succeed and get back
    the identical new pair, not a fresh pair each -- otherwise one of
    two legitimate concurrent refreshes ends up holding a token the
    other invalidated.
    """
    _, refresh_token = await _login_pair(client, "concurrent@example.com")

    first = await _refresh(client, refresh_token)
    assert first.status_code == 200

    second = await _refresh(client, refresh_token)
    assert second.status_code == 200

    assert first.json() == second.json()


@pytest.mark.asyncio(loop_scope="session")
async def test_reuse_after_grace_window_revokes_the_family(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Outside the grace window, replaying an already-rotated token is
    treated as reuse of a (presumably stolen) token: the whole family
    is revoked, and even the legitimate, currently-active token stops
    working.
    """
    monkeypatch.setattr(settings, "REFRESH_TOKEN_GRACE_PERIOD_SECONDS", 0)

    _, refresh_token = await _login_pair(client, "outside-window@example.com")

    first = await _refresh(client, refresh_token)
    assert first.status_code == 200
    latest_refresh_token = first.json()["refresh_token"]

    replay = await _refresh(client, refresh_token)
    assert replay.status_code == 401

    # The family (including the token issued by the first, legitimate
    # rotation) is now dead too.
    latest_attempt = await _refresh(client, latest_refresh_token)
    assert latest_attempt.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_reuse_of_token_older_than_direct_predecessor_revokes_family(
    client: AsyncClient,
) -> None:
    """Grace-window leniency only ever applies to the immediate
    predecessor of the currently active token. Once a second rotation
    has happened, replaying the *first* token is reuse of a stale link
    in the chain and must revoke the family outright, regardless of
    how little time has passed.
    """
    _, token_1 = await _login_pair(client, "old-token@example.com")

    rotate_1 = await _refresh(client, token_1)
    assert rotate_1.status_code == 200
    token_2 = rotate_1.json()["refresh_token"]

    rotate_2 = await _refresh(client, token_2)
    assert rotate_2.status_code == 200
    token_3 = rotate_2.json()["refresh_token"]

    # token_1's direct successor (token_2) has itself already been
    # rotated away -- token_1 is no longer eligible for the grace
    # window, even though barely any time has passed.
    reuse = await _refresh(client, token_1)
    assert reuse.status_code == 401

    # Family revocation takes down the currently-active token too.
    latest_attempt = await _refresh(client, token_3)
    assert latest_attempt.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_token_used_after_logout_returns_401(
    client: AsyncClient, auth_header
) -> None:
    access_token, refresh_token = await _login_pair(client, "logout@example.com")

    logout_response = await client.post(
        "/v1/auth/logout",
        headers=auth_header(access_token),
        json={"refresh_token": refresh_token},
    )
    assert logout_response.status_code == 204

    response = await _refresh(client, refresh_token)
    assert response.status_code == 401

@pytest.mark.asyncio(loop_scope="session")
async def test_logout_does_not_revoke_other_sessions(
    client: AsyncClient, auth_header, promote_to_admin
) -> None:
    """Logging out on one device/client must not knock out a refresh
    token that belongs to a different session for the same user."""
    email = "multi-device@example.com"
    access_token_a, refresh_token_a = await _login_pair(client, email)
    # /v1/chat/ is used below as a stand-in "protected route" to prove the
    # access token still works -- it requires the admin-only posts:read
    # permission, so this session's user needs the role explicitly since
    # there's no first-user-becomes-admin shortcut anymore.
    await promote_to_admin(email)
    login_b = await client.post(
        "/v1/auth/login", json={"email": email, "password": "password123"}
    )
    assert login_b.status_code == 200
    access_token_b = login_b.json()["access_token"]
    refresh_token_b = login_b.json()["refresh_token"]

    logout_response = await client.post(
        "/v1/auth/logout",
        headers=auth_header(access_token_a),
        json={"refresh_token": refresh_token_a},
    )
    assert logout_response.status_code == 204

    # Session A's refresh token is dead...
    response_a = await _refresh(client, refresh_token_a)
    assert response_a.status_code == 401

    # ...but session B's is untouched.
    response_b = await _refresh(client, refresh_token_b)
    assert response_b.status_code == 200

    # And session B's access token still works too.
    response = await client.get(
        "/v1/chat/", headers=auth_header(access_token_b)
    )
    assert response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_logout_all_revokes_every_session(
    client: AsyncClient, auth_header
) -> None:
    """POST /auth/logout-all ends every session for the user, unlike
    plain logout which only ends the current one."""
    email = "logout-all@example.com"
    access_token_a, refresh_token_a = await _login_pair(client, email)
    login_b = await client.post(
        "/v1/auth/login", json={"email": email, "password": "password123"}
    )
    assert login_b.status_code == 200
    access_token_b = login_b.json()["access_token"]
    refresh_token_b = login_b.json()["refresh_token"]

    logout_all_response = await client.post(
        "/v1/auth/logout-all", headers=auth_header(access_token_a)
    )
    assert logout_all_response.status_code == 204

    # Both sessions' refresh tokens are dead...
    assert (await _refresh(client, refresh_token_a)).status_code == 401
    assert (await _refresh(client, refresh_token_b)).status_code == 401

    # ...and both sessions' access tokens are blocked immediately, not
    # just the one used to call logout-all.
    response_a = await client.get("/v1/chat/", headers=auth_header(access_token_a))
    assert response_a.status_code == 401
    response_b = await client.get("/v1/chat/", headers=auth_header(access_token_b))
    assert response_b.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_unknown_refresh_token_returns_401(client: AsyncClient) -> None:
    response = await _refresh(client, "not-a-real-token")
    assert response.status_code == 401
