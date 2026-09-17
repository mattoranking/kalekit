import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

from kalekit.auth.client_type import ClientType


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str
    # Which client this login is for -- validated input (an unknown
    # value 422s rather than silently falling back), stamped onto the
    # issued tokens (RefreshToken.client, the access token's `aud`) and
    # what determines this session's token lifetimes (see #6). Defaults
    # to `web` so existing callers that don't send it keep working.
    client: ClientType = ClientType.web


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    # Required: without it, logout can only block the access token and
    # has no way to know which session's refresh token to revoke,
    # leaving it able to mint fresh access tokens until it expires on
    # its own -- that's not "ending the session". A well-behaved
    # client always has this (it was returned at login alongside the
    # access token). See /auth/logout-all to end every session at once.
    refresh_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class MessageResponse(BaseModel):
    detail: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    email_verified: bool
    created_at: datetime
    roles: list[str] = []

    model_config = {"from_attributes": True}


class SessionResponse(BaseModel):
    # The refresh token family id -- this *is* the session id: revoking
    # it (DELETE /auth/sessions/{id}) ends every refresh token that
    # shares it. See kalekit.models.refresh_token.RefreshToken.family_id.
    id: uuid.UUID
    device_info: str | None
    ip_address: str | None
    created_at: datetime
    last_used_at: datetime
    is_current: bool


class SessionListResponse(BaseModel):
    items: list[SessionResponse]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    # Plain `str`, not `EmailStr` -- deliberately, same reasoning as
    # `LoginRequest.email`: a malformed value still gets the identical
    # uniform 202 every other request gets, instead of a 422 that would
    # leak "this wasn't even shaped like an email" ahead of the
    # enumeration-safe response.
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ReauthenticateRequest(BaseModel):
    # Which of these is actually required depends on how the caller
    # authenticates (see #16): password accounts must provide
    # `password`; OAuth-only accounts (no password_hash) must provide
    # `oauth_ticket`, the single-use ticket minted by
    # /oauth/{provider}/callback after completing a fresh provider
    # login with `reauth=true`. Both fields are optional at the schema
    # level -- the endpoint itself enforces which one a given user
    # needs and gives a precise error if it's missing; a value in the
    # field that doesn't apply to the caller's account type is ignored.
    password: str | None = None
    oauth_ticket: str | None = None
