import os
from enum import StrEnum
from typing import Literal

from pydantic import Field, PostgresDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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

_GENERATE_SECRET_HINT = 'python3 -c "import secrets; print(secrets.token_urlsafe(48))"'


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
    # Value of the `iss` claim stamped on every access token and required
    # on decode, so a token minted by a different service or environment
    # that happens to share a signing key (e.g. a staging copy with a
    # copied secret) is rejected. Set it per deployment/environment.
    JWT_ISSUER: str = "kalekit"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # How long, after a refresh token is rotated, its immediate
    # predecessor may still be replayed and treated as a legitimate
    # concurrent refresh (returning the same new pair) instead of
    # triggering reuse detection. Needed because a BFF can run as
    # multiple instances, so two requests can race to refresh the same
    # token with no in-process lock to prevent it.
    REFRESH_TOKEN_GRACE_PERIOD_SECONDS: int = 45

    # Password length rule (see auth/password_policy.py): enforced when a
    # password is set (register); only the maximum is enforced at login.
    # Counted in characters. Length is the whole rule -- no composition
    # requirements (NIST SP 800-63B).
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=1)
    PASSWORD_MAX_LENGTH: int = Field(default=128, ge=1)

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Frontend (used to build links embedded in emails)
    FRONTEND_URL: str = "http://localhost:3000"

    # Organization invitations
    INVITATION_TOKEN_EXPIRE_HOURS: int = 72
    # Fixed-window rate limits on POST /organizations/{id}/invitations,
    # keyed separately by organization and by the inviting user so one
    # compromised/careless account in a busy org can't exhaust the other
    # limit meant to catch it. See issue #24 / RBAC #18 / #31.
    INVITATION_RATE_LIMIT_WINDOW_SECONDS: int = 3600
    INVITATION_RATE_LIMIT_PER_ORG: int = 20
    INVITATION_RATE_LIMIT_PER_INVITER: int = 10

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

    # Host header allow-list (comma-separated; "*.example.com" wildcards
    # allowed). Requests for any other Host get a 400. Set this to the
    # API's public hostname wherever it is deployed.
    ALLOWED_HOSTS: str = "localhost,127.0.0.1,testserver,test,api.kalekit.dev"

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
        # pydantic appends the (truncated) settings input to validation
        # errors, and its tail can be a real secret that then lands in
        # deploy logs.
        hide_input_in_errors=True,
    )

    @model_validator(mode="after")
    def _validate_password_length_bounds(self) -> "Settings":
        if self.PASSWORD_MIN_LENGTH > self.PASSWORD_MAX_LENGTH:
            raise ValueError(
                "KALEKIT_PASSWORD_MIN_LENGTH must not exceed "
                "KALEKIT_PASSWORD_MAX_LENGTH"
            )
        return self

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
                f"KALEKIT_JWT_SECRET_KEY is set to a known placeholder value "
                f"({secret!r}). Set a unique, random secret (32+ bytes) "
                f"before starting in a {self.ENV.value} environment -- "
                f"generate one with `{_GENERATE_SECRET_HINT}`."
            )

        secret_bytes = len(secret.encode("utf-8"))
        if secret_bytes < MIN_JWT_SECRET_KEY_BYTES:
            raise ValueError(
                f"KALEKIT_JWT_SECRET_KEY is too short ({secret_bytes} bytes; "
                f"minimum {MIN_JWT_SECRET_KEY_BYTES}). Generate one with "
                f"`{_GENERATE_SECRET_HINT}`."
            )

        return self

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
