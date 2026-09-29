from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.oauth_account import OAuthAccount
    from kalekit.models.organization import OrganizationMember
    from kalekit.models.refresh_token import RefreshToken


class User(RecordModel):
    __tablename__ = "users"
    __table_args__ = (
        # Partial unique index: enforces uniqueness only among non-NULL
        # emails, so multiple OAuth users whose provider never returned an
        # email (e.g. Twitter/X) can each be stored with email=NULL
        # instead of a fabricated, unverifiable "@oauth.local" address.
        Index(
            "ix_users_email_unique",
            "email",
            unique=True,
            postgresql_where=text("email IS NOT NULL"),
        ),
    )

    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Password sign-ups start unverified and must click an emailed link.
    # OAuth-created users are only marked verified when the provider
    # itself reports the email as verified (see oauth/repository.py).
    # Account linking trusts this flag to prevent a pre-hijack: an
    # attacker registers victim@example.com first, then the real owner
    # signs in with an OAuth provider using that address.
    email_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )

    # Relationships
    memberships: Mapped[list["OrganizationMember"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
