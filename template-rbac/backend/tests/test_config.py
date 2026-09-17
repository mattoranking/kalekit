from datetime import timedelta

import pytest

from kalekit.auth.client_type import ClientType
from kalekit.config import Environment, Settings


def _settings(env: Environment, secret: str) -> Settings:
    """Build a Settings instance in isolation from the process's real
    .env files, so these tests aren't sensitive to what's on disk.
    """
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        ENV=env,
        JWT_SECRET_KEY=secret,
    )


@pytest.mark.parametrize(
    "env", [Environment.development, Environment.testing]
)
@pytest.mark.parametrize(
    "secret", ["change-me-in-production", "change_me_in_production", "short"]
)
def test_dev_and_testing_allow_weak_secrets(env: Environment, secret: str) -> None:
    """Local development and the test suite must work out of the box,
    even with the placeholder secret .env.template / .env.testing ship.
    """
    settings = _settings(env, secret)

    assert settings.JWT_SECRET_KEY == secret


@pytest.mark.parametrize(
    "env",
    [
        Environment.preview,
        Environment.staging,
        Environment.production,
    ],
)
@pytest.mark.parametrize(
    "secret",
    ["change-me-in-production", "change_me_in_production", "CHANGE-ME-IN-PRODUCTION"],
)
def test_non_dev_environments_reject_default_secret(
    env: Environment, secret: str
) -> None:
    with pytest.raises(ValueError, match="placeholder"):
        _settings(env, secret)


@pytest.mark.parametrize(
    "env",
    [
        Environment.preview,
        Environment.staging,
        Environment.production,
    ],
)
def test_non_dev_environments_reject_short_secret(env: Environment) -> None:
    with pytest.raises(ValueError, match="too short"):
        _settings(env, "s" * 31)


@pytest.mark.parametrize(
    "env",
    [
        Environment.preview,
        Environment.staging,
        Environment.production,
    ],
)
def test_non_dev_environments_accept_strong_secret(env: Environment) -> None:
    settings = _settings(env, "s" * 32)

    assert settings.JWT_SECRET_KEY == "s" * 32


# --- Per-client token/session policy (see #6) -------------------------


def test_admin_gets_a_shorter_access_token_lifetime_than_web_and_mobile() -> None:
    """The suggested defaults (web/mobile 15m, admin 5m) from the
    issue's acceptance criteria: a compromised admin token should be
    live for less time than a compromised consumer one."""
    settings = _settings(Environment.testing, "s" * 32)

    admin_minutes = settings.access_token_expire_minutes(ClientType.admin)
    web_minutes = settings.access_token_expire_minutes(ClientType.web)
    mobile_minutes = settings.access_token_expire_minutes(ClientType.mobile)

    assert admin_minutes < web_minutes
    assert admin_minutes < mobile_minutes


def test_access_token_max_expire_minutes_is_the_longest_of_the_three() -> None:
    settings = _settings(Environment.testing, "s" * 32)

    assert settings.access_token_max_expire_minutes() == max(
        settings.ACCESS_TOKEN_EXPIRE_MINUTES_WEB,
        settings.ACCESS_TOKEN_EXPIRE_MINUTES_MOBILE,
        settings.ACCESS_TOKEN_EXPIRE_MINUTES_ADMIN,
    )


def test_admin_idle_timeout_is_far_shorter_than_web_and_mobile() -> None:
    """Suggested defaults: web/mobile 90 days, admin 30 minutes."""
    settings = _settings(Environment.testing, "s" * 32)

    assert settings.session_idle_timeout(ClientType.admin) == timedelta(minutes=30)
    assert settings.session_idle_timeout(ClientType.web) == timedelta(days=90)
    assert settings.session_idle_timeout(ClientType.mobile) == timedelta(days=90)


def test_web_and_mobile_have_no_absolute_session_timeout_by_default() -> None:
    """Consumer clients should keep an active user signed in
    indefinitely -- only a fixed idle timeout applies to them."""
    settings = _settings(Environment.testing, "s" * 32)

    assert settings.session_absolute_timeout(ClientType.web) is None
    assert settings.session_absolute_timeout(ClientType.mobile) is None


def test_admin_has_a_strict_absolute_session_timeout_by_default() -> None:
    """Suggested default: 12 hours, regardless of activity."""
    settings = _settings(Environment.testing, "s" * 32)

    assert settings.session_absolute_timeout(ClientType.admin) == timedelta(hours=12)
