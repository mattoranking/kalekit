import json
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from httpx import AsyncClient

from kalekit.auth.permissions import get_redis
from kalekit.auth.repository import get_refresh_token_by_hash
from kalekit.auth.service import hash_refresh_token
from kalekit.config import settings
from kalekit.oauth.client import OAUTH_PROVIDERS


async def _prime_state(
    client: AsyncClient,
    *,
    redirect_to: str | None = None,
    client_type: str | None = None,
) -> str:
    """Call the real /authorize endpoint to get a valid state token
    stored in Redis, exactly as the browser would obtain one."""
    params = {}
    if redirect_to is not None:
        params["redirect_to"] = redirect_to
    if client_type is not None:
        params["client"] = client_type
    response = await client.get(
        "/v1/oauth/github/authorize", params=params, follow_redirects=False
    )
    assert response.status_code == 200
    authorization_url = response.json()["authorization_url"]
    state = parse_qs(urlsplit(authorization_url).query)["state"][0]
    return state


def _mock_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    github = OAUTH_PROVIDERS["github"]

    async def fake_exchange_code(code: str, code_verifier: str | None = None) -> dict:
        return {"access_token": "provider-access-token"}

    async def fake_get_user_info(access_token: str) -> dict:
        return {"id": 999, "email": "oauth-user@example.com"}

    async def fake_email_verified(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr(github, "exchange_code", fake_exchange_code)
    monkeypatch.setattr(github, "get_user_info", fake_get_user_info)
    monkeypatch.setattr(
        "kalekit.oauth.endpoints._get_provider_email_verified", fake_email_verified
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_authorize_rejects_non_allowlisted_redirect(client: AsyncClient) -> None:
    response = await client.get(
        "/v1/oauth/github/authorize",
        params={"redirect_to": "https://evil.example.com/steal"},
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_authorize_accepts_default_frontend_url(client: AsyncClient) -> None:
    response = await client.get("/v1/oauth/github/authorize")

    assert response.status_code == 200
    assert "authorization_url" in response.json()


@pytest.mark.asyncio(loop_scope="session")
async def test_authorize_accepts_extra_allowlisted_origin(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        settings, "OAUTH_REDIRECT_ALLOWLIST", "https://admin.example.com"
    )

    response = await client.get(
        "/v1/oauth/github/authorize",
        params={"redirect_to": "https://admin.example.com/dashboard"},
    )

    assert response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_redirects_to_frontend_without_tokens_in_url(
    client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_provider(monkeypatch)
    state = await _prime_state(client)

    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(settings.FRONTEND_URL)

    query = parse_qs(urlsplit(location).query)
    assert list(query.keys()) == ["code"]
    exchange_code = query["code"][0]

    # No JWT-shaped material anywhere in the redirect target.
    assert "access_token" not in location
    assert "refresh_token" not in location

    # And the code is a fresh opaque value, not a token itself.
    assert exchange_code
    assert "." not in exchange_code  # JWTs contain dots; this must not be one


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_persists_a_refresh_token_row(
    client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_provider(monkeypatch)
    state = await _prime_state(client)

    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )
    location = response.headers["location"]
    exchange_code = parse_qs(urlsplit(location).query)["code"][0]

    exchange_response = await client.post(
        "/v1/oauth/exchange", json={"code": exchange_code}
    )
    assert exchange_response.status_code == 200
    refresh_token = exchange_response.json()["refresh_token"]

    token_row = await get_refresh_token_by_hash(
        session, hash_refresh_token(refresh_token)
    )
    assert token_row is not None
    assert token_row.revoked is False


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_issued_refresh_token_can_be_used_to_refresh(
    client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_provider(monkeypatch)
    state = await _prime_state(client)

    callback_response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )
    location = callback_response.headers["location"]
    exchange_code = parse_qs(urlsplit(location).query)["code"][0]

    exchange_response = await client.post(
        "/v1/oauth/exchange", json={"code": exchange_code}
    )
    refresh_token = exchange_response.json()["refresh_token"]

    refresh_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )

    assert refresh_response.status_code == 200
    assert refresh_response.json()["access_token"]


@pytest.mark.asyncio(loop_scope="session")
async def test_exchange_code_is_single_use(
    client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_provider(monkeypatch)
    state = await _prime_state(client)

    callback_response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )
    location = callback_response.headers["location"]
    exchange_code = parse_qs(urlsplit(location).query)["code"][0]

    first = await client.post("/v1/oauth/exchange", json={"code": exchange_code})
    assert first.status_code == 200

    second = await client.post("/v1/oauth/exchange", json={"code": exchange_code})
    assert second.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_exchange_rejects_unknown_code(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/oauth/exchange", json={"code": "not-a-real-code"}
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_rejects_state_whose_redirect_was_since_disallowed(
    client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If an operator narrows the allowlist between /authorize and
    /callback (e.g. state survives a config change), the callback must
    not honor a now-disallowed redirect target rather than trusting
    whatever was cached in Redis."""
    monkeypatch.setattr(
        settings, "OAUTH_REDIRECT_ALLOWLIST", "https://admin.example.com"
    )
    state = await _prime_state(client, redirect_to="https://admin.example.com/done")

    # Narrow the allowlist back down before the callback runs.
    monkeypatch.setattr(settings, "OAUTH_REDIRECT_ALLOWLIST", "")
    _mock_provider(monkeypatch)

    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_rejects_invalid_state(client: AsyncClient) -> None:
    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": "bogus-state"},
        follow_redirects=False,
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_rejects_state_with_a_corrupted_client(
    client: AsyncClient,
) -> None:
    """A `client` value in the Redis-stored OAuth state that isn't one
    of ClientType's members -- corrupted state, a manual edit, or a
    mid-deploy mismatch between an older /authorize and a newer
    /callback -- must be rejected with a 400, not surface as an
    unhandled ValueError (500). Same bug class, same fix pattern, as
    the corrupted `refresh_tokens.client` case in
    tests/auth/test_session_lifetime.py. See the round-3 Copilot
    review on PR #75."""
    state = await _prime_state(client)

    r = await get_redis()
    state_key = f"oauth_state:{state}"
    raw_state_data = await r.get(state_key)
    assert raw_state_data is not None
    state_data = json.loads(raw_state_data)
    state_data["client"] = "not-a-real-client"
    await r.set(state_key, json.dumps(state_data), ex=600)

    response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )

    assert response.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_authorize_rejects_unknown_client(client: AsyncClient) -> None:
    response = await client.get(
        "/v1/oauth/github/authorize", params={"client": "not-a-real-client"}
    )

    assert response.status_code == 422


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_login_mints_a_token_bound_to_the_requested_client(
    client: AsyncClient, session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The client requested at /authorize (e.g. "admin") is carried
    through the OAuth flow and stamped onto the minted access token's
    `aud` claim, exactly like a password login's `client` field. See
    #6."""
    _mock_provider(monkeypatch)
    state = await _prime_state(client, client_type="admin")

    callback_response = await client.get(
        "/v1/oauth/github/callback",
        params={"code": "provider-code", "state": state},
        follow_redirects=False,
    )
    location = callback_response.headers["location"]
    exchange_code = parse_qs(urlsplit(location).query)["code"][0]

    exchange_response = await client.post(
        "/v1/oauth/exchange", json={"code": exchange_code}
    )
    assert exchange_response.status_code == 200
    access_token = exchange_response.json()["access_token"]

    payload = jwt.decode(
        access_token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience="admin",
    )
    assert payload["aud"] == "admin"
