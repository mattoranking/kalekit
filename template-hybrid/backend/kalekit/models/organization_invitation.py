from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, Enum, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.models.organization import MemberRole
from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.organization import Organization
    from kalekit.models.user import User


class OrganizationInvitation(RecordModel):
    """A one-time, expiring invitation to join an organization at a
    specific role.

    Only the sha256 hash of the raw token is stored -- the raw token is
    only ever in the emailed link -- mirroring
    `EmailVerificationToken`/`RefreshToken` in RBAC. `accepted_at` makes
    the invitation single-use: once consumed it's kept (not deleted) as
    an audit trail, but `get_valid_invitation_by_token_hash` never
    returns it again.

    `role` is the role being offered, fixed at invite time -- but
    granting it is re-checked against `invited_by`'s *current* role in
    the organization when the invitation is accepted, not just at
    invite time, since the inviter may have been demoted (or removed)
    in between (see `organization/endpoints.py::accept_invitation`).

    No membership is created at invite time. `email` is only ever
    compared against the *authenticated* accepting user's own email --
    it is never used to look up whether an account with that email
    exists, which is exactly what let any member enumerate registered
    users before this fix (issue #24 / #31).
    """

    __tablename__ = "organization_invitations"

    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    role: Mapped[MemberRole] = mapped_column(
        Enum(MemberRole, native_enum=False, length=20), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    invited_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    organization: Mapped["Organization"] = relationship()
    inviter: Mapped["User | None"] = relationship()
