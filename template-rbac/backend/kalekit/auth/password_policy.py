"""The one password-length rule, shared by every endpoint that sets a
password (register, change-password, reset-password) and by the CLI.

Length is the whole rule -- no composition requirements (NIST SP
800-63B). The bounds are settings (PASSWORD_MIN_LENGTH /
PASSWORD_MAX_LENGTH), read at validation time, and counted in
characters. The minimum is enforced only where a password is *set*,
never at login, so accounts created before the rule existed can still
sign in and change their password.

The maximum exists so an attacker cannot make the server hash a
multi-megabyte password. It is checked before anything is hashed or
verified. This template verifies Argon2 hashes only, and the length
check runs before any hasher, so no input reaches one unbounded. (If a
bcrypt verifier is ever added, it truncates at 72 bytes; that would not
be a new risk either, for the same reason.)
"""

from typing import Annotated

from pydantic import AfterValidator

from kalekit.config import settings


def password_too_long(password: str) -> bool:
    return len(password) > settings.PASSWORD_MAX_LENGTH


def validate_password_length(password: str) -> str:
    """Return `password` unchanged, or raise ValueError (which Pydantic
    turns into a 422 with this message)."""
    low, high = settings.PASSWORD_MIN_LENGTH, settings.PASSWORD_MAX_LENGTH
    if not low <= len(password) <= high:
        raise ValueError(f"Password must be between {low} and {high} characters")
    return password


# Use for a password being *set*. Do not use for login or for verifying
# an existing password.
NewPassword = Annotated[str, AfterValidator(validate_password_length)]
