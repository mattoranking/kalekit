import pytest

from kalekit.config import Environment, settings
from kalekit.utils.email import ConsoleEmailSender, get_email_sender


def test_get_email_sender_returns_console_sender_in_testing() -> None:
    # The test suite always runs with KALEKIT_ENV=testing.
    assert settings.is_testing()
    assert isinstance(get_email_sender(), ConsoleEmailSender)


def test_get_email_sender_raises_outside_dev_and_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ConsoleEmailSender` logs secrets (invitation tokens) via structlog
    -- it must never be the silent default anywhere outside dev/test,
    or a real deployment could leak them into application logs."""
    monkeypatch.setattr(settings, "ENV", Environment.production)

    with pytest.raises(RuntimeError):
        get_email_sender()
