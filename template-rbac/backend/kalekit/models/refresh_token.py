from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel
from kalekit.utils.func import generate_uuid, utc_now

if TYPE_CHECKING:
    from kalekit.models.user import User


class RefreshToken(RecordModel):
    __tablename__ = "refresh_tokens"

    user_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)

    # All tokens issued from the same original login/OAuth exchange share a
    # family_id. Rotation carries it forward; reuse of an already-rotated
    # token in the family revokes every token that shares it (see
    # kalekit.auth.repository.revoke_refresh_token_family).
    family_id: Mapped[UUID] = mapped_column(
        Uuid, nullable=False, index=True, default=generate_uuid
    )

    # Set to the id of the token that replaced this one when it is rotated.
    # Combined with `revoked` and `updated_at` (the rotation timestamp),
    # this implements the grace window: the immediate predecessor of the
    # currently-active token can be replayed for a short time after
    # rotation without triggering reuse detection, so two callers racing
    # to refresh the same token both succeed.
    replaced_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("refresh_tokens.id"), nullable=True, default=None
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    device_info: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))

    # Session activity. Set to "now" every time a row is inserted for
    # this family (login, or each refresh rotation) -- since a family
    # gets a new row on every rotation, the most recent row's
    # last_used_at is the session's last-used time. See
    # kalekit.auth.repository.list_user_sessions.
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
