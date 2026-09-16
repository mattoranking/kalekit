import pytest

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
