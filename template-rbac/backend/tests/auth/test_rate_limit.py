"""Coverage for auth-endpoint rate limiting (issue #18): without it,
password guessing and account enumeration are only slowed by hashing
cost.

Rate limiting is off by default in tests (KALEKIT_RATE_LIMIT_ENABLED=false
in .env.testing) so the rest of the suite -- which logs in/registers the
same handful of emails, often from the same "unknown" client IP under the
ASGI test transport -- doesn't trip these limits as a side effect. Each
test here explicitly re-enables it and dials the relevant threshold down
so it can be exercised in a handful of requests.
"""

import pytest
from fastapi import Request
from httpx import AsyncClient

from kalekit.config import settings
from kalekit.utils.rate_limit import get_client_ip


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
    """Regression test (round-1 Copilot finding on PR #88): the login
    handler's per-account "peek" path (a plain GET, since only a failed
    attempt should increment the counter) didn't re-arm a missing TTL
    the way check_and_increment does, so an account key that somehow
    lost its expiry -- e.g. a crash between a prior INCR and its
    EXPIRE -- would block that account forever instead of recovering
    after the window, once the peek path started short-circuiting
    every request before check_and_increment ever ran again."""
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

    from kalekit.auth.permissions import get_redis

    r = await get_redis()
    account_key = "login_rate:account:ttl-recovery@example.com"
    # Simulate the crash-between-INCR-and-EXPIRE scenario directly,
    # rather than waiting out a real race: strip the key's TTL while
    # leaving its count (which is already >= the limit of 1) intact.
    await r.persist(account_key)
    assert await r.ttl(account_key) == -1

    blocked = await client.post(
        "/v1/auth/login",
        json={"email": "ttl-recovery@example.com", "password": "correct-password"},
    )
    assert blocked.status_code == 429
    # The peek path must have re-armed the TTL instead of leaving it
    # at -1 forever. Checked against -1 rather than "> 0": with a
    # 1-second window, Redis's TTL can legitimately have already
    # rounded down to 0 by the time this assertion runs, which isn't a
    # sign of a bug -- only "still has no expiry at all" is (round-4
    # Copilot finding on PR #88).
    assert await r.ttl(account_key) != -1


@pytest.mark.asyncio(loop_scope="session")
async def test_an_oversized_email_still_gets_rate_limited(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test (round-2 Copilot finding on PR #88): LoginRequest
    .email has no length cap, so an oversized value must still be
    throttled -- via a hashed key (see bounded_identifier) rather than
    the raw string blowing up Redis key size."""
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

    from kalekit.auth.permissions import get_redis
    from kalekit.utils.rate_limit import bounded_identifier

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

    first = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert first.status_code == 200

    new_refresh_token = first.json()["refresh_token"]
    second = await client.post(
        "/v1/auth/refresh", json={"refresh_token": new_refresh_token}
    )
    assert second.status_code == 429
    assert "Retry-After" in second.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_resend_verification_is_rate_limited_per_user(
    client: AsyncClient, register, login, auth_header, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RESEND_VERIFICATION_RATE_LIMIT_PER_USER", 1)

    await register("resend-limit@example.com", "correct-password")
    token = await login("resend-limit@example.com", "correct-password")

    first = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
    )
    assert first.status_code == 200

    second = await client.post(
        "/v1/auth/resend-verification", headers=auth_header(token)
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


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_is_rate_limited_per_account(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_ACCOUNT", 1)
    monkeypatch.setattr(settings, "PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_IP", 1000)

    await register("forgot-rate-account@example.com", "password12345")

    first = await client.post(
        "/v1/auth/password/forgot",
        json={"email": "forgot-rate-account@example.com"},
    )
    assert first.status_code == 202

    blocked = await client.post(
        "/v1/auth/password/forgot",
        json={"email": "forgot-rate-account@example.com"},
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_account_limit_also_applies_to_unknown_emails(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-account limit has to throttle unregistered emails
    exactly like real ones -- otherwise the limiter itself would leak
    which emails are registered (blocked = real account, never blocked
    = unknown)."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_ACCOUNT", 1)
    monkeypatch.setattr(settings, "PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_IP", 1000)

    first = await client.post(
        "/v1/auth/password/forgot",
        json={"email": "forgot-rate-unknown@example.com"},
    )
    assert first.status_code == 202

    blocked = await client.post(
        "/v1/auth/password/forgot",
        json={"email": "forgot-rate-unknown@example.com"},
    )
    assert blocked.status_code == 429


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_is_rate_limited_per_ip(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_IP", 1)
    monkeypatch.setattr(
        settings, "PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_ACCOUNT", 1000
    )

    first = await client.post(
        "/v1/auth/password/forgot",
        json={"email": "forgot-rate-ip-a@example.com"},
    )
    assert first.status_code == 202

    blocked = await client.post(
        "/v1/auth/password/forgot",
        json={"email": "forgot-rate-ip-b@example.com"},
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


@pytest.mark.asyncio(loop_scope="session")
async def test_reset_password_is_rate_limited_per_ip(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "PASSWORD_RESET_RATE_LIMIT_PER_IP", 1)

    first = await client.post(
        "/v1/auth/password/reset",
        json={"token": "not-a-real-token-a", "new_password": "whatever12345"},
    )
    assert first.status_code == 400

    blocked = await client.post(
        "/v1/auth/password/reset",
        json={"token": "not-a-real-token-b", "new_password": "whatever12345"},
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_get_client_ip_uses_the_first_forwarded_for_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)

    request = _request_with_forwarded_for("198.51.100.4, 203.0.113.9")

    assert get_client_ip(request) == "198.51.100.4"


def test_get_client_ip_falls_back_when_the_forwarded_for_header_is_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test (round-3 Copilot finding on PR #88): a leading
    empty entry (e.g. a header of ", 1.2.3.4") must not produce an
    empty-string IP -- that would collapse every client sending such a
    header onto the same Redis key (`login_rate:ip:`), letting one
    attacker's malformed header contaminate other callers' throttling."""
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
