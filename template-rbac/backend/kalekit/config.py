import os
from enum import StrEnum
from typing import Literal

from pydantic import Field, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

type PostgresDriver = Literal["psycopg2", "asyncpg"]


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
    # Required `aud` claim on access tokens -- pinning it (rather than
    # accepting any audience) keeps a token minted for one purpose from
    # being replayed against an API that happens to trust the same
    # signing key for something else.
    JWT_AUDIENCE: str = "kalekit-api"
    # Clock-skew tolerance (seconds) applied when checking `exp` during
    # decode, so a slightly-behind server clock doesn't reject
    # otherwise-valid tokens right at their expiry boundary.
    JWT_LEEWAY_SECONDS: int = 30
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
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


settings = Settings()

__all__ = ["Environment", "Settings", "settings"]
