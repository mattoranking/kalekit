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
