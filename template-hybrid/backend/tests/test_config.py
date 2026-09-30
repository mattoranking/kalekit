import pytest

from kalekit.config import Environment, Settings

NON_DEV_ENVIRONMENTS = [
    Environment.preview,
    Environment.staging,
    Environment.production,
]


def _settings(env: Environment, secret: str) -> Settings:
    """Build a Settings instance in isolation from the process's real
    .env files, so these tests aren't sensitive to what's on disk.
    """
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        ENV=env,
        JWT_SECRET_KEY=secret,
    )


@pytest.mark.parametrize("env", [Environment.development, Environment.testing])
@pytest.mark.parametrize(
    "secret", ["change-me-in-production", "change_me_in_production", "short"]
)
def test_dev_and_testing_allow_weak_secrets(env: Environment, secret: str) -> None:
    """Local development and the test suite must work out of the box,
    even with the placeholder secret .env.template / .env.testing ship.
    """
    settings = _settings(env, secret)

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


def test_default_secret_is_rejected_when_no_secret_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case #163 is about: a deployment that forgets to set the
    secret at all falls back to the built-in default and must not boot.
    """
    monkeypatch.delenv("KALEKIT_JWT_SECRET_KEY", raising=False)
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
def test_rejected_error_does_not_echo_settings_secrets(env: Environment) -> None:
    """pydantic appends `input_value=<settings dict>` to validation errors,
    truncated to its head and tail, and the tail is whichever fields sit
    last in the dict. Here that is the OAuth client secret, so a secret
    that is not the rejected one would still end up in deploy logs.
    """
    oauth_secret = "tw-client-secret-Zx81QpLm9Vc4"

    with pytest.raises(ValueError) as excinfo:
        Settings(
            _env_file=None,  # type: ignore[call-arg]
            ENV=env,
            JWT_SECRET_KEY="Rk9vQmFyQmF6UXV4MTIzNDU2",  # 24 bytes: too short
            TWITTER_CLIENT_SECRET=oauth_secret,
        )

    message = str(excinfo.value)
    assert "too short" in message
    # pydantic truncates the echoed value, so look for its tail end.
    assert oauth_secret[-12:] not in message
    assert "input_value" not in message
