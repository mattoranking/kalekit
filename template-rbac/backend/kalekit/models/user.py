from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kalekit.utils.db.models import RecordModel

if TYPE_CHECKING:
    from kalekit.models.oauth_account import OAuthAccount
    from kalekit.models.refresh_token import RefreshToken
    from kalekit.models.role import UserRole


class User(RecordModel):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Password sign-ups start unverified and must click an emailed link.
    # OAuth-created users are only marked verified when the provider
    # itself reports the email as verified (see oauth/repository.py) --
    # this flag is what account-linking trusts to prevent a pre-hijack
    # (attacker registers victim@example.com first, then the real owner
    # signs in with an OAuth provider using that address).
    email_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # "Sign out everywhere" counter. Access tokens carry the value they
    # were issued under (`ver` claim) and get_current_user rejects any
    # token whose value differs from this one. Change-password, password
    # reset and logout-all bump it in the same transaction as their other
    # changes (see kalekit.auth.repository.bump_token_version), so the
    # cut-off holds even when the Redis blocklist can't be written (#195).
    # A counter rather than a timestamp: access-token `iat` is whole
    # seconds, so a timestamp can't tell a token issued just before the
    # change from one issued just after it in the same second.
    token_version: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    # Relationships
    roles: Mapped[list["UserRole"]] = relationship(
        back_populates="user", lazy="selectin"
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
