import os
from datetime import timedelta
from enum import StrEnum
from typing import Literal

from pydantic import Field, PostgresDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from kalekit.auth.client_type import ClientType

type PostgresDriver = Literal["psycopg2", "asyncpg"]

# Placeholder values that ship in config defaults / .env.template / the
# project generator. None of these are safe to sign tokens with -- anyone
# who reads this source (or the template) knows them too.
INSECURE_JWT_SECRETS = {
    "change-me-in-production",
    "change_me_in_production",
    "dev-only-not-secret",
}

# JWT_SECRET_KEY is used as an HMAC key (HS256). 32 bytes is the minimum
# recommended key size for HMAC-SHA256 -- shorter keys are brute-forceable.
MIN_JWT_SECRET_KEY_BYTES = 32


class Environment(StrEnum):
    development = "development"
    testing = "testing"
    preview = "preview"
    staging = "staging"
    production = "production"


env = Environment(os.getenv("KALEKIT_ENV", Environment.development))
if env == Environment.testing:
    env_file = ".env.testing"
elif env == Environment.preview:
    env_file = ".env.preview"
else:
    env_file = ".env"


class Settings(BaseSettings):
    ENV: Environment = Environment.development
    DEBUG: bool = False

    # Auth / JWT
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    # Identifies which key signed a given access token (carried in the
    # token's `kid` header). New tokens are always signed with
    # JWT_SECRET_KEY under this kid.
    JWT_KID: str = "primary"
    # Previous signing keys, keyed by the `kid` they were issued under.
    # A token whose `kid` matches one of these still verifies, so a
    # secret can be rotated (bump JWT_KID, set a new JWT_SECRET_KEY, and
    # move the old key in here) without invalidating every outstanding
    # token. Drop an entry once nothing signed under it should still be
    # accepted (e.g. past its max access-token lifetime).
    JWT_PREVIOUS_KEYS: dict[str, str] = Field(default_factory=dict)
    # Clock-skew tolerance (seconds) applied when checking `exp` during
    # decode, so a slightly-behind server clock doesn't reject
    # otherwise-valid tokens right at their expiry boundary.
    JWT_LEEWAY_SECONDS: int = 30

    # --- Per-client token policy (see #6) ---
    #
    # Every access token's `aud` claim is the client (web/mobile/admin)
    # it was minted for -- decode() (see auth/dependencies.py) accepts
    # any of ClientType's values as a valid audience, then
    # `require_admin_client` narrows individual routes down to exactly
    # `admin`. This is what stops a web/mobile session -- even one for
    # a user who holds the admin role -- from being replayed against
    # admin-only routes: those need a token actually minted by the
    # admin client, not merely a token whose scopes happen to include
    # admin permissions.
    #
    # Admin sessions get shorter-lived access tokens than the consumer
    # clients since a compromised admin token is far more dangerous.
    ACCESS_TOKEN_EXPIRE_MINUTES_WEB: int = 15
    ACCESS_TOKEN_EXPIRE_MINUTES_MOBILE: int = 15
    ACCESS_TOKEN_EXPIRE_MINUTES_ADMIN: int = 5

    # Sliding session expiration for refresh tokens: every successful
    # /auth/refresh issues a new refresh token whose `expires_at` is
    # `now + <client>'s idle timeout`, so an actively-used session never
    # hits it. See auth/service.py:generate_refresh_token.
    SESSION_IDLE_TIMEOUT_DAYS_WEB: int = 90
    SESSION_IDLE_TIMEOUT_DAYS_MOBILE: int = 90
    SESSION_IDLE_TIMEOUT_MINUTES_ADMIN: int = 30

    # Absolute session lifetime: a session (token family) is forced to
    # end this long after the *original* login/OAuth exchange, no
    # matter how active it's been -- measured from
    # RefreshToken.family_created_at, which rotation carries forward
    # unchanged (unlike `expires_at`, the idle timeout, which rotation
    # resets). None means "no absolute cutoff" -- appropriate for
    # consumer clients, which should keep an active user signed in
    # indefinitely; the back office stays strict.
    SESSION_ABSOLUTE_TIMEOUT_DAYS_WEB: int | None = None
    SESSION_ABSOLUTE_TIMEOUT_DAYS_MOBILE: int | None = None
    SESSION_ABSOLUTE_TIMEOUT_HOURS_ADMIN: int | None = 12

    # How long a role's resolved permission set is cached in Redis
    # (auth/permissions.py:get_permissions_for_roles). Kept short: with
    # `require_permission` now resolving permissions live on every
    # request instead of trusting the access token's baked-in scopes
    # (see #6), this TTL is the only remaining delay between an admin
    # revoking a role's permission and it actually taking effect.
    ROLE_CACHE_TTL_SECONDS: int = 60

    # How long, after a refresh token is rotated, its immediate
    # predecessor may still be replayed and treated as a legitimate
    # concurrent refresh (returning the same new pair) instead of
    # triggering reuse detection. Needed because the web BFF runs as
    # multiple serverless instances, so two requests can race to refresh
    # the same token with no in-process lock to prevent it.
    REFRESH_TOKEN_GRACE_PERIOD_SECONDS: int = 45

    # Email verification
    # When True, unverified accounts can't log in at all. When False
    # (default), they can log in but require_verified_email gates
    # anything beyond profile/resend-verification -- a kit can flip
    # this per its own risk tolerance.
    REQUIRE_EMAIL_VERIFICATION_BEFORE_LOGIN: bool = False
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    FRONTEND_URL: str = "http://localhost:3000"

    # Password reset (#17). Deliberately much shorter-lived than an
    # email-verification token -- this one authorizes an account
    # takeover if intercepted, not just an email-ownership proof. Kept
    # within the 15-60 minute range #17 calls for.
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # Extra origins (beyond FRONTEND_URL, which is always allowed) the
    # OAuth callback may redirect back to after login. Comma-separated
    # full URLs or bare origins, e.g.
    # "https://app.example.com,https://admin.example.com". Anything not
    # matching one of these origins is rejected to prevent the callback
    # being used as an open redirect.
    OAUTH_REDIRECT_ALLOWLIST: str = ""

    # How long a post-OAuth-login exchange code lives in Redis before it
    # expires unused. Kept short: it's single-use and only has to survive
    # the browser redirect from /oauth/{provider}/callback to the
    # frontend, which then immediately exchanges it server-side.
    OAUTH_EXCHANGE_CODE_TTL_SECONDS: int = 60

    # --- Rate limiting (#18) ---
    # Guards the auth endpoints most exposed to brute force, enumeration
    # and abuse. On by default; flipped off in .env.testing so the rest
    # of the suite (which logs in/registers the same handful of emails,
    # and shares one "unknown" client IP under the ASGI test transport)
    # doesn't trip these limits as a side effect -- a dedicated test
    # module flips it back on with tight thresholds to exercise the
    # limiter itself.
    RATE_LIMIT_ENABLED: bool = True

    # Login: limited both by IP (protects against credential stuffing
    # across many accounts from one source) and by target account
    # (protects one account against password guessing spread across
    # many IPs) -- either one alone misses the other attack shape.
    LOGIN_RATE_LIMIT_PER_IP: int = 10
    LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS: int = 60
    # Only failed attempts count against the per-account limit (a
    # successful login clears the counter) -- a legitimate user mistyping
    # their password a few times shouldn't lock out the next correct
    # attempt any sooner than this budget allows.
    LOGIN_RATE_LIMIT_PER_ACCOUNT: int = 5
    LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS: int = 900  # 15 minutes

    # Registration: per-IP only -- there's no "account" yet to key on.
    REGISTER_RATE_LIMIT_PER_IP: int = 5
    REGISTER_RATE_LIMIT_WINDOW_SECONDS: int = 3600

    # Refresh: keyed per session (refresh token family) once the
    # presented token resolves to one, not per IP -- a session is
    # legitimately used from a changing IP (mobile networks, VPNs), and
    # the token itself is already the unguessable secret.
    REFRESH_RATE_LIMIT_PER_SESSION: int = 60
    REFRESH_RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Resend-verification: authenticated, so keyed per user rather than
    # per IP -- caps how many verification emails one account can
    # trigger in a window.
    RESEND_VERIFICATION_RATE_LIMIT_PER_USER: int = 5
    RESEND_VERIFICATION_RATE_LIMIT_WINDOW_SECONDS: int = 3600

    # Forgot-password (#17): unauthenticated and the classic account-
    # enumeration oracle, so -- like login -- it's throttled both by IP
    # (credential-stuffing-style abuse across many addresses) and by the
    # submitted email itself (protects one mailbox from being flooded
    # with reset emails). Unlike login's account limit, this one counts
    # *every* request against the email, not just "failures" -- there is
    # no failure/success distinction visible to the caller here (the
    # response is identical either way), so counting unconditionally is
    # what keeps the limiter itself from leaking which emails are
    # registered.
    PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_IP: int = 10
    PASSWORD_RESET_REQUEST_RATE_LIMIT_IP_WINDOW_SECONDS: int = 3600
    PASSWORD_RESET_REQUEST_RATE_LIMIT_PER_ACCOUNT: int = 3
    PASSWORD_RESET_REQUEST_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS: int = 3600

    # Reset (token redemption): per IP, guarding against brute-forcing
    # the token itself -- there's no "account" to key on since the token
    # is presented without any other identifying credential.
    PASSWORD_RESET_RATE_LIMIT_PER_IP: int = 20
    PASSWORD_RESET_RATE_LIMIT_WINDOW_SECONDS: int = 3600

    # Only trust `X-Forwarded-For` (set by Traefik -- see compose.yml)
    # for IP-keyed rate limiting when the API actually sits behind a
    # proxy that sets it honestly. On a direct connection, any client
    # could set that header itself to claim a fresh IP on every request
    # and dodge IP-based limiting entirely -- so this defaults to off,
    # and a deployment behind Traefik/another trusted proxy opts in.
    TRUST_PROXY_HEADERS: bool = False

    # How long a post-OAuth-*re-authentication* ticket lives in Redis
    # before it expires unused (see /oauth/{provider}/callback's `reauth`
    # branch and POST /auth/reauthenticate, #16). Same shape as
    # OAUTH_EXCHANGE_CODE_TTL_SECONDS -- single-use, only has to survive
    # the browser redirect back to the frontend -- kept as a separate
    # setting rather than reusing that one so the two can be tuned
    # independently (a re-auth ticket has no reason to share a TTL with
    # a fresh-login exchange code just because they're both short-lived).
    OAUTH_REAUTH_TICKET_TTL_SECONDS: int = 60

    # Step-up re-authentication (#16): how old a session's last proven
    # authentication (password re-entry, or a fresh OAuth provider login)
    # may be before `require_recent_auth` starts rejecting sensitive
    # actions with `reauth_required`. Applies uniformly regardless of
    # client -- a stolen session is exactly as dangerous on web as on
    # mobile or admin.
    REAUTH_MAX_AGE_MINUTES: int = 10

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Connection pool settings
    DATABASE_POOL_SIZE: int = 5
    DATABASE_SYNC_POOL_SIZE: int = 1
    DATABASE_POOL_RECYCLE_SECONDS: int = 300  # 5 minutes

    # Primary database (read-write)
    POSTGRES_USER: str = "postgres"
    POSTGRES_PWD: str = "postgres"
    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432
    POSTGRES_DATABASE: str = "kalekit_db"

    # Read replica (optional - falls back to primary if not set)
    POSTGRES_READ_HOST: str | None = None
    POSTGRES_READ_PORT: int | None = None

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000"

    # OAuth2 — GitHub
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:8000/v1/auth/oauth/github/callback"

    # OAuth2 — Google
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/v1/auth/oauth/google/callback"

    # OAuth2 — X (Twitter)
    TWITTER_CLIENT_ID: str = ""
    TWITTER_CLIENT_SECRET: str = ""
    TWITTER_REDIRECT_URI: str = "http://localhost:8000/v1/auth/oauth/twitter/callback"

    def get_postgres_dsn(self, driver: PostgresDriver) -> PostgresDsn:
        """Build DSN for the primary (read-write) database."""
        return PostgresDsn.build(
            scheme=f"postgresql+{driver}",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PWD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DATABASE,
        )

    def get_postgres_read_dsn(self, driver: PostgresDriver) -> PostgresDsn:
        """Build DSN for the read replica.
        Falls back to primary if not configured.
        """
        return PostgresDsn.build(
            scheme=f"postgresql+{driver}",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PWD,
            host=self.POSTGRES_READ_HOST or self.POSTGRES_HOST,
            port=self.POSTGRES_READ_PORT or self.POSTGRES_PORT,
            path=self.POSTGRES_DATABASE,
        )

    model_config = SettingsConfigDict(
        env_prefix="KALEKIT_",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_file=env_file,
        extra="allow",
    )

    def access_token_expire_minutes(self, client: ClientType) -> int:
        """Access token lifetime for `client`. Admin gets a shorter
        lifetime than the consumer clients -- see the field docstrings
        above."""
        return {
            ClientType.web: self.ACCESS_TOKEN_EXPIRE_MINUTES_WEB,
            ClientType.mobile: self.ACCESS_TOKEN_EXPIRE_MINUTES_MOBILE,
            ClientType.admin: self.ACCESS_TOKEN_EXPIRE_MINUTES_ADMIN,
        }[client]

    def access_token_max_expire_minutes(self) -> int:
        """The longest access token lifetime across all clients.

        Used as the default Redis TTL for the token/user/family
        blocklists (auth/permissions.py) -- those entries just need to
        outlive whatever access token they're guarding against, and the
        blocking code path doesn't always know which client minted the
        token it's blocking. Erring long (rather than per-client) is
        the safe direction: it never lets a blocked token work again
        early.
        """
        return max(
            self.ACCESS_TOKEN_EXPIRE_MINUTES_WEB,
            self.ACCESS_TOKEN_EXPIRE_MINUTES_MOBILE,
            self.ACCESS_TOKEN_EXPIRE_MINUTES_ADMIN,
        )

    def session_idle_timeout(self, client: ClientType) -> timedelta:
        """How long a session may sit unused before its refresh token
        stops working. Reset on every successful refresh."""
        if client is ClientType.admin:
            return timedelta(minutes=self.SESSION_IDLE_TIMEOUT_MINUTES_ADMIN)
        days = (
            self.SESSION_IDLE_TIMEOUT_DAYS_WEB
            if client is ClientType.web
            else self.SESSION_IDLE_TIMEOUT_DAYS_MOBILE
        )
        return timedelta(days=days)

    def session_absolute_timeout(self, client: ClientType) -> timedelta | None:
        """How long after login a session is forced to end regardless
        of activity, or None for no cutoff."""
        if client is ClientType.admin:
            hours = self.SESSION_ABSOLUTE_TIMEOUT_HOURS_ADMIN
            return timedelta(hours=hours) if hours is not None else None
        days = (
            self.SESSION_ABSOLUTE_TIMEOUT_DAYS_WEB
            if client is ClientType.web
            else self.SESSION_ABSOLUTE_TIMEOUT_DAYS_MOBILE
        )
        return timedelta(days=days) if days is not None else None

    def is_read_replica_configured(self) -> bool:
        return self.POSTGRES_READ_HOST is not None

    def is_environment(self, environments: set[Environment]) -> bool:
        return self.ENV in environments

    def is_development(self) -> bool:
        return self.is_environment({Environment.development})

    def is_testing(self) -> bool:
        return self.is_environment({Environment.testing})

    def is_preview(self) -> bool:
        return self.is_environment({Environment.preview})

    def is_staging(self) -> bool:
        return self.is_environment({Environment.staging})

    def is_production(self) -> bool:
        return self.is_environment({Environment.production})

    @model_validator(mode="after")
    def _validate_jwt_secret_key(self) -> "Settings":
        """Refuse to start with a known-default or too-short JWT secret.

        Development and testing are exempt so the app still runs out of
        the box from .env.template / .env.testing without any setup --
        everywhere else (preview, staging, production), a weak secret
        would let anyone forge tokens, so we fail fast at startup instead
        of silently signing with it.
        """
        if self.is_environment({Environment.development, Environment.testing}):
            return self

        secret = self.JWT_SECRET_KEY
        if secret.lower() in INSECURE_JWT_SECRETS:
            raise ValueError(
                "KALEKIT_JWT_SECRET_KEY is set to a known placeholder value "
                f"({secret!r}). Set a unique, random secret (32+ bytes) "
                f"before starting in a {self.ENV.value} environment -- "
                "generate one with `uv run python -m kalekit.cli "
                "generate-secret`."
            )

        secret_bytes = len(secret.encode("utf-8"))
        if secret_bytes < MIN_JWT_SECRET_KEY_BYTES:
            raise ValueError(
                f"KALEKIT_JWT_SECRET_KEY is too short ({secret_bytes} bytes; "
                f"minimum {MIN_JWT_SECRET_KEY_BYTES}). Generate one with "
                "`uv run python -m kalekit.cli generate-secret`."
            )

        return self


settings = Settings()

__all__ = ["Environment", "Settings", "settings"]
