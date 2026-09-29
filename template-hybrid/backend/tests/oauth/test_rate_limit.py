"""Rate limiting on the OAuth endpoints (issue #166).

RBAC's PR #88 did not cover OAuth, so this is new coverage. Both
endpoints are unauthenticated and cheap to hit: `authorize` writes a
Redis key per call and `callback` triggers outbound calls to the
provider. Each is limited per client IP. Off in tests by default
(KALEKIT_RATE_LIMIT_ENABLED=false); each test re-enables it.
"""

import pytest
import redis.exceptions
from httpx import AsyncClient

from kalekit.config import settings


@pytest.mark.asyncio(loop_scope="session")
async def test_authorize_is_rate_limited_per_ip(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "OAUTH_RATE_LIMIT_PER_IP", 2)

    for _ in range(2):
        response = await client.get("/v1/oauth/github/authorize")
        assert response.status_code == 200

    blocked = await client.get("/v1/oauth/github/authorize")
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_is_rate_limited_per_ip(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "OAUTH_RATE_LIMIT_PER_IP", 2)

    for _ in range(2):
        response = await client.get(
            "/v1/oauth/github/callback", params={"code": "c", "state": "no-such"}
        )
        assert response.status_code == 400

    blocked = await client.get(
        "/v1/oauth/github/callback", params={"code": "c", "state": "no-such"}
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_authorize_and_callback_have_separate_counters(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "OAUTH_RATE_LIMIT_PER_IP", 1)

    assert (await client.get("/v1/oauth/github/authorize")).status_code == 200
    callback = await client.get(
        "/v1/oauth/github/callback", params={"code": "c", "state": "no-such"}
    )
    assert callback.status_code == 400


@pytest.mark.asyncio(loop_scope="session")
async def test_oauth_limits_are_off_by_default_in_tests(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "OAUTH_RATE_LIMIT_PER_IP", 1)
    assert settings.RATE_LIMIT_ENABLED is False

    for _ in range(3):
        assert (await client.get("/v1/oauth/github/authorize")).status_code == 200


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("endpoint", ["authorize", "callback"])
async def test_oauth_limiter_fails_open_when_the_counter_errors(
    endpoint: str, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Redis error inside the limiter itself is swallowed: the request
    reaches the handler and gets its normal answer. (The OAuth state
    store, which has no fallback, still fails closed -- see
    test_redis_failure.py.)"""

    async def _boom(*args: object, **kwargs: object) -> bool:
        raise redis.exceptions.ConnectionError("simulated redis outage")

    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr("kalekit.oauth.endpoints.check_and_increment", _boom)

    if endpoint == "authorize":
        response = await client.get("/v1/oauth/github/authorize")
        assert response.status_code == 200
    else:
        response = await client.get(
            "/v1/oauth/github/callback", params={"code": "c", "state": "no-such"}
        )
        assert response.status_code == 400
