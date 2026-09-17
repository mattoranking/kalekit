from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.user import User


class PasswordResetToken(RecordModel):
    """A one-time, expiring token proving control of the account's email
    for the purpose of resetting/setting its password.

    Same shape as `EmailVerificationToken` -- only the sha256 hash of the
    raw token is stored (the raw token is only ever in the emailed
    link), and `used_at` makes it single-use: once consumed it's kept
    (not deleted) as an audit trail, but a claimed/expired token is
    never treated as valid again. See
    `kalekit.auth.repository.claim_password_reset_token`.
    """

    __tablename__ = "password_reset_tokens"

    user_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship()
