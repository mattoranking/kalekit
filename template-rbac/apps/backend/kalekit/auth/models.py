from __future__ import annotations

from typing import Generic, TypeVar

from kalekit.auth.scope import Scope
from kalekit.models.user import User


class Anonymous:
    """Represents an unauthenticated caller."""

    pass


Subject = User | Anonymous
S = TypeVar("S", bound=Subject)


class AuthSubject(Generic[S]):
    subject: S
    scopes: set[Scope]
    session_id: str | None

    def __init__(
        self,
        subject: S,
        scopes: set[Scope],
        session_id: str | None = None,
    ) -> None:
        self.subject = subject
        self.scopes = scopes
        self.session_id = session_id

    @property
    def is_anonymous(self) -> bool:
        return isinstance(self.subject, Anonymous)
