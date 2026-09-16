"""Pluggable outbound email.

Only email verification uses this today. `ConsoleEmailSender` is the
default for local/dev/test -- it just logs the message instead of
sending it, so the kit works out of the box without SMTP credentials.
Swap `get_email_sender` for a real provider (SES, Postmark, Resend,
...) before shipping to production.
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
    return ConsoleEmailSender()


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


__all__ = [
    "ConsoleEmailSender",
    "EmailSender",
    "get_email_sender",
    "send_verification_email",
]
