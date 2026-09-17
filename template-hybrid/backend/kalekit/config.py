import os
from enum import StrEnum
from typing import Literal

from pydantic import PostgresDsn
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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

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
