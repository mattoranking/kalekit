import pytest
from structlog.testing import capture_logs

from kalekit.config import Environment, settings
from kalekit.utils.email import (
    ConsoleEmailSender,
    get_email_sender,
    send_password_reset_email,
    send_verification_email,
)


def test_get_email_sender_returns_console_sender_in_testing() -> None:
    # The test suite always runs with KALEKIT_ENV=testing.
    assert settings.is_testing()
    assert isinstance(get_email_sender(), ConsoleEmailSender)


@pytest.mark.parametrize(
    "environment",
    [
        Environment.development,
        Environment.testing,
        Environment.preview,
        Environment.staging,
    ],
)
def test_get_email_sender_returns_console_sender_outside_production(
    monkeypatch: pytest.MonkeyPatch, environment: Environment
) -> None:
    monkeypatch.setattr(settings, "ENV", environment)

    assert isinstance(get_email_sender(), ConsoleEmailSender)


def test_get_email_sender_raises_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ConsoleEmailSender` logs secrets (verification and password-reset
    tokens) via structlog -- it must never be the silent default in
    production, or a real deployment could leak them into its logs."""
    monkeypatch.setattr(settings, "ENV", Environment.production)

    with pytest.raises(RuntimeError):
        get_email_sender()


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "send",
    [send_verification_email, send_password_reset_email],
)
async def test_sending_in_production_raises_and_logs_no_token(
    monkeypatch: pytest.MonkeyPatch, send
) -> None:
    monkeypatch.setattr(settings, "ENV", Environment.production)

    with capture_logs() as logs, pytest.raises(RuntimeError):
        await send(to="user@example.com", token="secret-raw-token")

    assert "secret-raw-token" not in repr(logs)
