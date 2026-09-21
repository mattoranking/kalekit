from collections.abc import Callable, Coroutine

import pytest
from httpx import AsyncClient, Response

BASIC_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


def _assert_basic_headers(response: Response) -> None:
    for name, value in BASIC_HEADERS.items():
        assert response.headers.get(name) == value, name
    # HSTS belongs to Traefik on the HTTPS routers, never the app.
    assert "strict-transport-security" not in response.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_headers_on_normal_response(client: AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    _assert_basic_headers(response)
    assert "cache-control" not in response.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_headers_on_error_response(client: AsyncClient) -> None:
    response = await client.get("/no-such-route")

    assert response.status_code == 404
    _assert_basic_headers(response)


@pytest.mark.asyncio(loop_scope="session")
async def test_headers_on_validation_error(client: AsyncClient) -> None:
    response = await client.post("/v1/auth/login", json={})

    assert response.status_code == 422
    _assert_basic_headers(response)


@pytest.mark.asyncio(loop_scope="session")
async def test_disallowed_host_is_rejected(client: AsyncClient) -> None:
    response = await client.get("/health", headers={"Host": "evil.example.com"})

    assert response.status_code == 400
    # The rejection itself still carries the headers.
    _assert_basic_headers(response)


@pytest.mark.asyncio(loop_scope="session")
async def test_allowed_host_with_port_is_accepted(client: AsyncClient) -> None:
    response = await client.get("/health", headers={"Host": "localhost:8000"})

    assert response.status_code == 200


@pytest.mark.asyncio(loop_scope="session")
async def test_login_and_refresh_are_no_store(
    client: AsyncClient,
    register: Callable[..., Coroutine[None, None, Response]],
) -> None:
    assert (await register("headers@example.com")).status_code == 201

    login = await client.post(
        "/v1/auth/login",
        json={
            "email": "headers@example.com",
            "password": "password12345",
            "client": "web",
        },
    )
    assert login.status_code == 200
    assert login.headers["cache-control"] == "no-store"

    refresh = await client.post(
        "/v1/auth/refresh",
        json={"refresh_token": login.json()["refresh_token"]},
    )
    assert refresh.status_code == 200
    assert refresh.headers["cache-control"] == "no-store"


@pytest.mark.asyncio(loop_scope="session")
async def test_auth_error_responses_are_no_store(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@example.com", "password": "x" * 12, "client": "web"},
    )

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_paths_are_no_store(client: AsyncClient) -> None:
    response = await client.post("/v1/oauth/exchange", json={"code": "nope"})

    assert response.headers["cache-control"] == "no-store"
