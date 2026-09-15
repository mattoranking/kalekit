from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.user import User


class Role(RecordModel):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))

    users: Mapped[list["UserRole"]] = relationship(back_populates="role")
    permissions: Mapped[list["RolePermission"]] = relationship(
        back_populates="role", lazy="selectin"
    )


class Permission(RecordModel):
    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))

    roles: Mapped[list["RolePermission"]] = relationship(back_populates="permission")


class UserRole(RecordModel):
    __tablename__ = "user_roles"

    user_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("roles.id"), primary_key=True)

    user: Mapped["User"] = relationship(back_populates="roles")
    role: Mapped["Role"] = relationship(back_populates="users")


class RolePermission(RecordModel):
    __tablename__ = "role_permissions"

    role_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("roles.id"), primary_key=True)

    permission_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("permissions.id"), primary_key=True
    )

    role: Mapped["Role"] = relationship(back_populates="permissions")
    permission: Mapped["Permission"] = relationship(back_populates="roles")
