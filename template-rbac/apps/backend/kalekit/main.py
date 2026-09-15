from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TypedDict

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kalekit.api import router
from kalekit.config import settings
from kalekit.health.endpoints import router as health_router
from kalekit.logging import Logger, configure_logging
from kalekit.openapi import OPENAPI_PARAMETERS
from kalekit.postgres import (
    AsyncSessionMiddleware,
    create_async_engine,
    create_async_read_engine,
)
from kalekit.utils.db.database import (
    AsyncEngine,
    AsyncReadSessionMaker,
    AsyncSessionMaker,
    Engine,
    SessionMaker,
    create_async_read_sessionmaker,
    create_async_sessionmaker,
    create_sync_sessionmaker,
)

log: Logger = structlog.get_logger()


def configure_cors(app: FastAPI) -> None:
    origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


class State(TypedDict):
    async_engine: AsyncEngine
    async_sessionmaker: AsyncSessionMaker
    async_read_engine: AsyncEngine
    async_read_sessionmaker: AsyncReadSessionMaker
    sync_engine: Engine
    sync_sessionmaker: SessionMaker


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[State]:
    """Lifespan event for the FastAPI application."""
    log.info("Lifespan - Starting up the application...")
    async_engine = async_read_engine = create_async_engine("kalekit")
    async_sessionmaker = create_async_sessionmaker(async_engine)

    if settings.is_read_replica_configured():
        async_read_engine = create_async_read_engine("kalekit")
        log.info("read_replica_enabled", host=settings.POSTGRES_READ_HOST)

    async_read_sessionmaker = create_async_read_sessionmaker(async_read_engine)

    # Sync engine (for migrations, scripts)
    from kalekit.postgres import create_sync_engine as _create_sync_engine

    sync_engine = _create_sync_engine("kalekit")
    sync_sessionmaker = create_sync_sessionmaker(sync_engine)

    log.info("Kalekit API Started...")

    yield {
        "async_engine": async_engine,
        "async_sessionmaker": async_sessionmaker,
        "async_read_engine": async_read_engine,
        "async_read_sessionmaker": async_read_sessionmaker,
        "sync_engine": sync_engine,
        "sync_sessionmaker": sync_sessionmaker,
    }

    # Cleanup
    await async_engine.dispose()
    if async_read_engine is not async_engine:
        await async_read_engine.dispose()

    sync_engine.dispose()

    log.info("Lifespan - Shutting down the application...")
    pass


def create_app() -> FastAPI:
    app = FastAPI(
        **OPENAPI_PARAMETERS,
        lifespan=lifespan,
    )

    configure_cors(app)

    if not settings.is_testing():
        app.add_middleware(AsyncSessionMiddleware)

    # /health
    app.include_router(health_router)

    app.include_router(router)

    return app


# Module-level initialization
configure_logging(
    level="DEBUG" if settings.DEBUG else "INFO", json_output=settings.is_production()
)

app = create_app()
