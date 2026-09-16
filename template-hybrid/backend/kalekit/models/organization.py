from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Enum, ForeignKey, Index, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.user import User


class MemberRole(StrEnum):
    owner = "owner"
    admin = "admin"
    member = "member"
    viewer = "viewer"


class Organization(RecordModel):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)

    members: Mapped[list["OrganizationMember"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class OrganizationMember(RecordModel):
    """Membership plus a role — fixed to the membership, not the user.

    The same person can be `owner` in one organization and `member` in
    another, because the role lives here rather than on `User`. The
    four roles are fixed in code (see auth/roles.py), not a
    DB-configurable catalog like the RBAC template's Role/Permission
    tables — most real multi-tenant products hardcode a small role
    set rather than letting each org define its own.
    """

    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "user_id", name="uq_organization_members_org_user"
        ),
        Index("ix_organization_members_user_id", "user_id"),
    )

    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id"), nullable=False)
    role: Mapped[MemberRole] = mapped_column(
        Enum(MemberRole, native_enum=False, length=20), nullable=False
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="members", lazy="selectin"
    )
    user: Mapped["User"] = relationship(back_populates="memberships")
