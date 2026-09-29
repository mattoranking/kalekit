"""Pluggable outbound email.

Ported from RBAC #7. Organization invitations and email verification use
this.
`ConsoleEmailSender` is used in every environment except production -- it
just logs the message instead of sending it, so the kit works out of the
box without SMTP credentials. Swap `get_email_sender` for a real provider
(SES, Postmark, Resend, ...) before shipping to production.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import structlog

from kalekit.config import settings
from kalekit.models.organization import MemberRole

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
    """Returns the outbound email sender to use.

    `ConsoleEmailSender` in development, testing, preview and staging,
    where printing the full link -- including its raw, otherwise-secret
    token -- to the server console instead of delivering it is intended.
    In production this raises rather than silently falling back to it:
    doing so would leak invitation and verification tokens (and any
    future secrets routed through this module) straight into
    application logs. Wire up a real provider (SES, Postmark, Resend,
    ...) here before shipping to production.
    """
    if not settings.is_production():
        return ConsoleEmailSender()
    raise RuntimeError(
        "No production EmailSender is configured. ConsoleEmailSender logs "
        "secrets (e.g. invitation and verification tokens) and must not "
        "run in production -- wire up a real provider in "
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
            f"{settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS} hours and can "
            "only be used once."
        ),
    )


async def send_invitation_email(
    *, to: str, organization_name: str, token: str, role: MemberRole
) -> None:
    """Emails an org invitation link.

    Deliberately fires unconditionally, whether or not `to` belongs to
    a registered user -- the caller (POST .../invitations) never checks
    that, so this function can't leak it either. Accepting the
    invitation is where the recipient's identity actually gets checked,
    against the *authenticated* user's email.

    `role` is surfaced in the body only -- it's informational for the
    invitee, not a security boundary. The actual grant is re-checked
    against the inviter's *current* role at accept time (see
    `organization/endpoints.py::accept_invitation`), since it may have
    changed since the invite was sent.
    """
    accept_url = f"{settings.FRONTEND_URL}/invitations/accept?token={token}"
    sender = get_email_sender()
    await sender.send(
        to=to,
        subject=f"You've been invited to join {organization_name}",
        body=(
            f"You've been invited to join {organization_name} on Kalekit as "
            f"a {role.value}. Accept the invitation by visiting the link "
            f"below:\n\n{accept_url}\n\n"
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
    "send_verification_email",
]
