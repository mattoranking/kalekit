"""Pluggable outbound email.

Email verification and password reset use this today. `ConsoleEmailSender` is
used in every environment except production -- it just logs the message
instead of sending it, so the kit works out of the box without SMTP
credentials. Swap `get_email_sender` for a real provider (SES, Postmark,
Resend, ...) before shipping to production.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import structlog

from kalekit.config import settings

logger = structlog.get_logger()


class EmailSender(ABC):
    @abstractmethod
    async def send(self, *, to: str, subject: str, body: str) -> None: ...


class ConsoleEmailSender(EmailSender):
    """Logs the email instead of delivering it. Good enough for
    development and tests -- and for reading the verification link
    straight out of the logs before a real provider is wired up."""

    async def send(self, *, to: str, subject: str, body: str) -> None:
        logger.info("email.send", to=to, subject=subject, body=body)


def get_email_sender() -> EmailSender:
    """Returns the outbound email sender to use.

    `ConsoleEmailSender` in development, testing, preview and staging,
    where printing the full link -- including its raw, otherwise-secret
    token -- to the server console instead of delivering it is intended.
    In production this raises rather than silently falling back to it:
    doing so would leak verification and password-reset tokens (and any
    future secrets routed through this module) straight into
    application logs. Wire up a real provider (SES, Postmark, Resend,
    ...) here before shipping to production.
    """
    if not settings.is_production():
        return ConsoleEmailSender()
    raise RuntimeError(
        "No production EmailSender is configured. ConsoleEmailSender logs "
        "secrets (e.g. verification and password-reset tokens) and must "
        "not run in production -- wire up a real provider in "
        "get_email_sender() before deploying."
    )


async def send_verification_email(*, to: str, token: str) -> None:
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    sender = get_email_sender()
    await sender.send(
        to=to,
        subject="Verify your email address",
        body=(
            "Welcome! Please verify your email address by visiting the "
            f"link below:\n\n{verify_url}\n\n"
            "This link expires in "
            f"{settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS} hours."
        ),
    )


async def send_password_reset_email(*, to: str, token: str) -> None:
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    sender = get_email_sender()
    await sender.send(
        to=to,
        subject="Reset your password",
        body=(
            "We received a request to reset the password for this "
            f"account. Visit the link below to choose a new one:\n\n"
            f"{reset_url}\n\n"
            "If you didn't request this, you can safely ignore this "
            "email -- your password won't change.\n\n"
            "This link expires in "
            f"{settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes."
        ),
    )


__all__ = [
    "ConsoleEmailSender",
    "EmailSender",
    "get_email_sender",
    "send_password_reset_email",
    "send_verification_email",
]
