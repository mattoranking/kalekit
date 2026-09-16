from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.user import User


class EmailVerificationToken(RecordModel):
    """A one-time, expiring token proving control of the account's email.

    Only the sha256 hash of the raw token is stored -- the raw token is
    only ever in the emailed link -- mirroring how RefreshToken never
    stores the raw refresh token either. `used_at` makes the token
    single-use: once consumed it's kept (not deleted) as an audit trail,
    but `get_valid_verification_token` never returns it again.
    """

    __tablename__ = "email_verification_tokens"

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
