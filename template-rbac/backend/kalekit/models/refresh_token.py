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

    # Which client (web/mobile/admin -- see kalekit.auth.client_type.
    # ClientType) this token was issued to. Stored as a plain string
    # rather than a DB enum, matching Scope/Role/Permission elsewhere in
    # this app; the client_type module is the single source of truth
    # for which values are valid. Carried forward unchanged on rotation
    # (a session can't change client mid-flight). See #6.
    client: Mapped[str] = mapped_column(
        String(16), nullable=False, default="web", server_default="web"
    )

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

    # The *original* login/OAuth exchange's timestamp for this token's
    # family -- i.e. the session's absolute start. Every row in a
    # family carries the same value forward across rotations (unlike
    # `expires_at`, which slides forward on each refresh); it's what
    # lets a session be force-ended a fixed time after login regardless
    # of activity (the "absolute timeout" half of the sliding
    # expiration policy -- see #6 and
    # kalekit.config.Settings.session_absolute_timeout). Defaults to
    # "now" so a brand-new family's first row needs no explicit value;
    # rotation must pass the predecessor's value through explicitly.
    family_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
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
