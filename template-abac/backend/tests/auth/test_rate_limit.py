"""Coverage for auth-endpoint rate limiting (port of RBAC #18 / PR #88):
without it, password guessing and account enumeration are only slowed by
hashing cost.

Rate limiting is off by default in tests (KALEKIT_RATE_LIMIT_ENABLED=false
in .env.testing) so the rest of the suite -- which logs in/registers the
same handful of emails, all from the same client IP under the ASGI test
transport -- doesn't trip these limits as a side effect. Each test here
explicitly re-enables it and dials the relevant threshold down so it can
be exercised in a handful of requests.
"""

import asyncio

import pytest
import redis.exceptions
from fastapi import Request
from httpx import AsyncClient

from kalekit.config import settings
from kalekit.redis import get_redis
from kalekit.utils.rate_limit import (
    bounded_identifier,
    check_and_increment,
    get_client_ip,
)


def _request_with_forwarded_for(value: str | None) -> Request:
    """Build a minimal Request carrying the given X-Forwarded-For header
    (or none, if `value` is None), with a real ASGI-style peer address
    so the fallback path has something concrete to fall back to."""
    headers = []
    if value is not None:
        headers.append((b"x-forwarded-for", value.encode()))
    scope = {
        "type": "http",
        "headers": headers,
        "client": ("203.0.113.9", 12345),
    }
    return Request(scope)


@pytest.mark.asyncio(loop_scope="session")
async def test_repeated_failed_logins_for_one_account_are_blocked(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 3)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1000)

    await register("bruteforced@example.com", "correct-password")

    for _ in range(3):
        response = await client.post(
            "/v1/auth/login",
            json={"email": "bruteforced@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 401

    blocked = await client.post(
        "/v1/auth/login",
        json={"email": "bruteforced@example.com", "password": "wrong-password"},
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers

    # Even the *correct* password is blocked while the account is
    # rate-limited -- the whole point is to slow down guessing
    # regardless of whether the next guess happens to be right.
    still_blocked = await client.post(
        "/v1/auth/login",
        json={"email": "bruteforced@example.com", "password": "correct-password"},
    )
    assert still_blocked.status_code == 429


@pytest.mark.asyncio(loop_scope="session")
async def test_failed_logins_for_an_unknown_email_are_also_blocked(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-account limit has to apply to unregistered emails too --
    otherwise the limiter itself would leak which emails are registered
    (blocked = real account, never blocked = unknown)."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 2)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1000)

    for _ in range(2):
        response = await client.post(
            "/v1/auth/login",
            json={"email": "nobody-at-all@example.com", "password": "whatever"},
        )
        assert response.status_code == 401

    blocked = await client.post(
        "/v1/auth/login",
        json={"email": "nobody-at-all@example.com", "password": "whatever"},
    )
    assert blocked.status_code == 429


@pytest.mark.asyncio(loop_scope="session")
async def test_a_blocked_login_looks_the_same_for_known_and_unknown_emails(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rate-limited login must not reveal whether the account exists:
    the 429 status, body and Retry-After presence are identical for a
    registered email and an unregistered one."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 1)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1000)

    await register("known-blocked@example.com", "correct-password")

    responses = []
    for email in ("known-blocked@example.com", "unknown-blocked@example.com"):
        first = await client.post(
            "/v1/auth/login", json={"email": email, "password": "wrong-password"}
        )
        assert first.status_code == 401
        responses.append(
            await client.post(
                "/v1/auth/login",
                json={"email": email, "password": "wrong-password"},
            )
        )

    known, unknown = responses
    assert known.status_code == unknown.status_code == 429
    assert known.json() == unknown.json()
    assert "Retry-After" in known.headers
    assert "Retry-After" in unknown.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_a_successful_login_clears_the_account_failure_count(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 2)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1000)

    await register("recovers@example.com", "correct-password")

    # One failure, then a success -- should reset the counter rather
    # than leave it at 1/2.
    fail = await client.post(
        "/v1/auth/login",
        json={"email": "recovers@example.com", "password": "wrong-password"},
    )
    assert fail.status_code == 401

    success = await client.post(
        "/v1/auth/login",
        json={"email": "recovers@example.com", "password": "correct-password"},
    )
    assert success.status_code == 200

    # Two more failures shouldn't be blocked yet -- if the counter
    # hadn't been cleared, this would already be the 3rd failure
    # against a limit of 2.
    for _ in range(2):
        response = await client.post(
            "/v1/auth/login",
            json={"email": "recovers@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_account_lockout_recovers_when_its_redis_key_loses_its_ttl(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The login handler's per-account "peek" path (a plain GET, since
    only a failed attempt should increment the counter) has to re-arm a
    missing TTL the way check_and_increment does. Otherwise an account
    key that lost its expiry -- e.g. a crash between a prior INCR and its
    EXPIRE -- would block that account forever."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 1)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS", 1)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1000)

    await register("ttl-recovery@example.com", "correct-password")

    fail = await client.post(
        "/v1/auth/login",
        json={"email": "ttl-recovery@example.com", "password": "wrong-password"},
    )
    assert fail.status_code == 401

    r = await get_redis()
    account_key = "login_rate:account:ttl-recovery@example.com"
    # Simulate the crash-between-INCR-and-EXPIRE scenario directly:
    # strip the key's TTL while leaving its count (already >= the limit
    # of 1) intact.
    await r.persist(account_key)
    assert await r.ttl(account_key) == -1

    blocked = await client.post(
        "/v1/auth/login",
        json={"email": "ttl-recovery@example.com", "password": "correct-password"},
    )
    assert blocked.status_code == 429
    # Checked against -1 rather than "> 0": with a 1-second window the
    # TTL can legitimately have rounded down to 0 by now; only "still no
    # expiry at all" is a bug.
    assert await r.ttl(account_key) != -1


@pytest.mark.asyncio(loop_scope="session")
async def test_an_oversized_email_still_gets_rate_limited(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LoginRequest.email has no length cap, so an oversized value must
    still be throttled -- via a hashed key (see bounded_identifier)
    rather than the raw string becoming an unbounded Redis key."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 1)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1000)

    huge_email = "a" * 10_000 + "@example.com"

    fail = await client.post(
        "/v1/auth/login",
        json={"email": huge_email, "password": "whatever"},
    )
    assert fail.status_code == 401

    blocked = await client.post(
        "/v1/auth/login",
        json={"email": huge_email, "password": "whatever"},
    )
    assert blocked.status_code == 429

    r = await get_redis()
    hashed_key = f"login_rate:account:{bounded_identifier(huge_email.lower())}"
    assert len(hashed_key) < 200
    assert await r.get(hashed_key) is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_login_is_also_rate_limited_per_ip(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-IP limit catches credential stuffing spread across many
    different accounts from one source, which the per-account limit
    alone wouldn't."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 2)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 1000)

    await register("ip-limit-a@example.com", "correct-password")
    await register("ip-limit-b@example.com", "correct-password")

    first = await client.post(
        "/v1/auth/login",
        json={"email": "ip-limit-a@example.com", "password": "correct-password"},
    )
    assert first.status_code == 200

    second = await client.post(
        "/v1/auth/login",
        json={"email": "ip-limit-b@example.com", "password": "wrong-password"},
    )
    assert second.status_code == 401

    third = await client.post(
        "/v1/auth/login",
        json={"email": "ip-limit-b@example.com", "password": "correct-password"},
    )
    assert third.status_code == 429
    assert "Retry-After" in third.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_register_is_rate_limited_per_ip(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "REGISTER_RATE_LIMIT_PER_IP", 1)

    first = await client.post(
        "/v1/auth/register",
        json={"email": "register-limit-a@example.com", "password": "password12345"},
    )
    assert first.status_code == 201

    second = await client.post(
        "/v1/auth/register",
        json={"email": "register-limit-b@example.com", "password": "password12345"},
    )
    assert second.status_code == 429
    assert "Retry-After" in second.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_refresh_is_rate_limited_per_session(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "REFRESH_RATE_LIMIT_PER_SESSION", 1)

    await register("refresh-limit@example.com", "correct-password")
    login_response = await client.post(
        "/v1/auth/login",
        json={"email": "refresh-limit@example.com", "password": "correct-password"},
    )
    refresh_token = login_response.json()["refresh_token"]

    first = await client.post("/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert first.status_code == 200

    new_refresh_token = first.json()["refresh_token"]
    second = await client.post(
        "/v1/auth/refresh", json={"refresh_token": new_refresh_token}
    )
    assert second.status_code == 429
    assert "Retry-After" in second.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_rate_limiting_can_be_disabled(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Confirms the kill switch itself: with RATE_LIMIT_ENABLED left at
    its default (off in tests), a threshold this low still doesn't
    block anything."""
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 1)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1)
    assert settings.RATE_LIMIT_ENABLED is False

    await register("disabled-limit@example.com", "correct-password")

    for _ in range(5):
        response = await client.post(
            "/v1/auth/login",
            json={
                "email": "disabled-limit@example.com",
                "password": "wrong-password",
            },
        )
        assert response.status_code == 401


def test_get_client_ip_uses_the_first_forwarded_for_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)

    request = _request_with_forwarded_for("198.51.100.4, 203.0.113.9")

    assert get_client_ip(request) == "198.51.100.4"


def test_get_client_ip_falls_back_when_the_forwarded_for_header_is_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A leading empty entry (e.g. ", 1.2.3.4") must not produce an
    empty-string IP -- that would collapse every client sending such a
    header onto the same Redis key."""
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)

    request = _request_with_forwarded_for(", 1.2.3.4")

    assert get_client_ip(request) == "203.0.113.9"


def test_get_client_ip_falls_back_when_the_forwarded_for_header_is_only_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)

    request = _request_with_forwarded_for("   ")

    assert get_client_ip(request) == "203.0.113.9"


def test_get_client_ip_ignores_forwarded_for_when_proxy_headers_are_not_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)

    request = _request_with_forwarded_for("198.51.100.4")

    assert get_client_ip(request) == "203.0.113.9"


# --- Redis outage: the limiter fails open -----------------------------------


class _DeadRedis:
    """Every command raises, like a Redis that has gone away."""

    def __getattr__(self, name: str):
        async def _fail(*args: object, **kwargs: object) -> None:
            raise redis.exceptions.ConnectionError("simulated redis outage")

        return _fail


async def _dead_get_redis() -> _DeadRedis:
    return _DeadRedis()


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "endpoint",
    ["register", "login_success", "login_wrong_password", "refresh"],
)
async def test_rate_limited_auth_endpoints_allow_the_request_when_redis_is_down(
    endpoint: str,
    client: AsyncClient,
    register,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rate limiting is an abuse control, not an authorization gate, so
    an outage must not take these endpoints down: each behaves exactly
    as if rate limiting were off (its normal answer, not a 500 from the
    Redis error and not a 429)."""
    email = f"rl-outage-{endpoint}@example.com"
    await register(email, "correct-password")
    login = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correct-password"}
    )
    assert login.status_code == 200
    refresh_token = login.json()["refresh_token"]

    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr("kalekit.auth.endpoints.get_redis", _dead_get_redis)

    if endpoint == "register":
        response = await client.post(
            "/v1/auth/register",
            json={"email": "rl-outage-new@example.com", "password": "password12345"},
        )
        expected = 201
    elif endpoint == "login_success":
        response = await client.post(
            "/v1/auth/login", json={"email": email, "password": "correct-password"}
        )
        expected = 200
    elif endpoint == "login_wrong_password":
        response = await client.post(
            "/v1/auth/login", json={"email": email, "password": "wrong-password"}
        )
        expected = 401
    else:
        response = await client.post(
            "/v1/auth/refresh", json={"refresh_token": refresh_token}
        )
        expected = 200

    assert response.status_code == expected, response.text


@pytest.mark.asyncio(loop_scope="session")
async def test_parallel_attempts_cannot_get_past_the_account_limit() -> None:
    """The login account limit relies on `check_and_increment` being
    atomic: 20 simultaneous attempts against a limit of 3 must let exactly
    3 through, not all 20 (which a read-then-increment scheme would, since
    every request would read the old count)."""
    r = await get_redis()

    results = await asyncio.gather(
        *(
            check_and_increment(
                r, "login_rate:account:race@example.com", limit=3, window_seconds=60
            )
            for _ in range(20)
        )
    )

    assert results.count(True) == 3
    assert results.count(False) == 17


@pytest.mark.asyncio(loop_scope="session")
async def test_parallel_wrong_passwords_are_capped_by_the_account_limit(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: with a limit of 3, 10 wrong passwords sent at once
    must not all be answered 401. Exactly 3 reach the password check and
    the rest get 429."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 3)
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT_PER_IP", 1000)

    await register("parallel-guess@example.com", "correct-password")

    responses = await asyncio.gather(
        *(
            client.post(
                "/v1/auth/login",
                json={
                    "email": "parallel-guess@example.com",
                    "password": f"wrong-{i}",
                },
            )
            for i in range(10)
        )
    )

    codes = sorted(r.status_code for r in responses)
    assert codes == [401] * 3 + [429] * 7
