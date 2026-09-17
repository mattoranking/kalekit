from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.user import User


class Organization(RecordModel):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # The only user allowed to invite new members (see issue #24): flat
    # membership means every member can read/write the org's data, but
    # growing the tenant is not something membership alone should grant
    # -- otherwise any member could pull arbitrary registered users into
    # the org unilaterally. Nullable so a future admin-created or
    # system-seeded organization isn't forced to have a human creator.
    created_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=True
    )

    members: Mapped[list["OrganizationMember"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class OrganizationMember(RecordModel):
    """Flat membership — no role column.

    Everyone who belongs to an organization has identical access to
    its data; the gate is membership itself, not what you're allowed
    to do once you're in. This mirrors Polar's UserOrganization table.
    """

    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id"),
    )

    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=False, index=True
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="members", lazy="selectin"
    )
    user: Mapped["User"] = relationship(back_populates="memberships")
