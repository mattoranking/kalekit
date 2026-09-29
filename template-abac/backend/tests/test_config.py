import pytest

from kalekit.config import Environment, Settings

NON_DEV_ENVIRONMENTS = [
    Environment.preview,
    Environment.staging,
    Environment.production,
]


def _settings(
    env: Environment,
    secret: str,
    previous_keys: dict[str, str] | None = None,
) -> Settings:
    """Build a Settings instance in isolation from the process's real
    .env files, so these tests aren't sensitive to what's on disk.
    """
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        ENV=env,
        JWT_SECRET_KEY=secret,
        JWT_PREVIOUS_KEYS=previous_keys or {},
    )


@pytest.mark.parametrize("env", [Environment.development, Environment.testing])
@pytest.mark.parametrize(
    "secret", ["change-me-in-production", "change_me_in_production", "short"]
)
def test_dev_and_testing_allow_weak_secrets(env: Environment, secret: str) -> None:
    """Local development and the test suite must work out of the box,
    even with the placeholder secret .env.template / .env.testing ship.
    """
    settings = _settings(env, secret, {"old": "short"})

    assert settings.JWT_SECRET_KEY == secret


@pytest.mark.parametrize("env", NON_DEV_ENVIRONMENTS)
@pytest.mark.parametrize(
    "secret",
    [
        "change-me-in-production",
        "change_me_in_production",
        "dev-only-not-secret",
        "CHANGE-ME-IN-PRODUCTION",
    ],
)
def test_non_dev_environments_reject_default_secret(
    env: Environment, secret: str
) -> None:
    with pytest.raises(ValueError, match="placeholder"):
        _settings(env, secret)


def test_default_secret_is_rejected_when_no_secret_is_configured() -> None:
    """The case #163 is about: a deployment that forgets to set the
    secret at all falls back to the built-in default and must not boot.
    """
    with pytest.raises(ValueError, match="placeholder"):
        Settings(_env_file=None, ENV=Environment.production)  # type: ignore[call-arg]


@pytest.mark.parametrize("env", NON_DEV_ENVIRONMENTS)
def test_non_dev_environments_reject_short_secret(env: Environment) -> None:
    with pytest.raises(ValueError, match="too short"):
        _settings(env, "s" * 31)


@pytest.mark.parametrize("env", NON_DEV_ENVIRONMENTS)
def test_non_dev_environments_accept_strong_secret(env: Environment) -> None:
    settings = _settings(env, "s" * 32)

    assert settings.JWT_SECRET_KEY == "s" * 32


@pytest.mark.parametrize("env", NON_DEV_ENVIRONMENTS)
def test_non_dev_environments_reject_placeholder_previous_key(
    env: Environment,
) -> None:
    """A rotated-out key still verifies tokens, so a known default parked
    in JWT_PREVIOUS_KEYS lets anyone forge tokens under that kid.
    """
    with pytest.raises(ValueError, match="JWT_PREVIOUS_KEYS.*placeholder"):
        _settings(env, "s" * 32, {"old": "change-me-in-production"})


@pytest.mark.parametrize("env", NON_DEV_ENVIRONMENTS)
def test_non_dev_environments_reject_short_previous_key(env: Environment) -> None:
    with pytest.raises(ValueError, match="JWT_PREVIOUS_KEYS.*too short"):
        _settings(env, "s" * 32, {"old": "s" * 31})


@pytest.mark.parametrize("env", NON_DEV_ENVIRONMENTS)
def test_non_dev_environments_accept_strong_previous_key(env: Environment) -> None:
    settings = _settings(env, "s" * 32, {"old": "o" * 32})

    assert settings.JWT_PREVIOUS_KEYS == {"old": "o" * 32}


@pytest.mark.parametrize("env", NON_DEV_ENVIRONMENTS)
def test_rejected_secret_value_is_not_echoed_in_the_error(env: Environment) -> None:
    """pydantic appends `input_value=<settings dict>` to validation errors,
    truncated to its head and tail, and that tail can hold a real secret
    (here the last field set) that ends up in deploy logs.
    """
    secret = "Rk9vQmFyQmF6UXV4MTIzNDU2"  # 24 bytes: fails the length check

    with pytest.raises(ValueError) as excinfo:
        _settings(env, secret)

    assert "too short" in str(excinfo.value)
    assert secret not in str(excinfo.value)
    assert "input_value" not in str(excinfo.value)
