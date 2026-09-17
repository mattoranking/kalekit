"""Pluggable outbound email.

Ported from RBAC #7. Only organization invitations use this today.
`ConsoleEmailSender` is the default for local/dev/test -- it just logs
the message instead of sending it, so the kit works out of the box
without SMTP credentials. Swap `get_email_sender` for a real provider
(SES, Postmark, Resend, ...) before shipping to production.
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
    development and tests -- and for reading the invitation link
    straight out of the logs before a real provider is wired up."""

    async def send(self, *, to: str, subject: str, body: str) -> None:
        logger.info("email.send", to=to, subject=subject, body=body)


def get_email_sender() -> EmailSender:
    return ConsoleEmailSender()


async def send_invitation_email(
    *, to: str, organization_name: str, token: str
) -> None:
    """Emails an org invitation link.

    Deliberately fires unconditionally, whether or not `to` belongs to
    a registered user -- the caller (POST .../invitations) never checks
    that, so this function can't leak it either. Accepting the
    invitation is where the recipient's identity actually gets checked,
    against the *authenticated* user's email.
    """
    accept_url = f"{settings.FRONTEND_URL}/invitations/accept?token={token}"
    sender = get_email_sender()
    await sender.send(
        to=to,
        subject=f"You've been invited to join {organization_name}",
        body=(
            f"You've been invited to join {organization_name} on Kalekit. "
            f"Accept the invitation by visiting the link below:\n\n{accept_url}\n\n"
            "This link expires in "
            f"{settings.INVITATION_TOKEN_EXPIRE_HOURS} hours and can only be "
            "used once, by someone signed in with this email address."
        ),
    )


__all__ = [
    "ConsoleEmailSender",
    "EmailSender",
    "get_email_sender",
    "send_invitation_email",
]
