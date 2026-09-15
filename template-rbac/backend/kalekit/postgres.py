from collections.abc import AsyncGenerator
from typing import Literal

from fastapi import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from kalekit.config import settings
from kalekit.utils.db.database import (
    AsyncEngine,
    AsyncReadSession,
    AsyncReadSessionMaker,
    AsyncSession,
    AsyncSessionMaker,
    Engine,
)
from kalekit.utils.db.database import create_async_engine as _create_async_engine
from kalekit.utils.db.database import create_sync_engine as _create_sync_engine

type ProcessName = Literal["kalekit"]


def create_async_engine(process_name: ProcessName) -> AsyncEngine:
    return _create_async_engine(
        dsn=str(settings.get_postgres_dsn("asyncpg")),
        application_name=f"{settings.ENV.value}.{process_name}",
        pool_logging_name=process_name,
        debug=settings.DEBUG,
        pool_size=settings.DATABASE_POOL_SIZE,
        pool_recycle=settings.DATABASE_POOL_RECYCLE_SECONDS,
    )


def create_async_read_engine(process_name: ProcessName) -> AsyncEngine:
    """Create engine for the read replica."""
    return _create_async_engine(
        dsn=str(settings.get_postgres_read_dsn("asyncpg")),
        application_name=f"{settings.ENV.value}.{process_name}",
        pool_logging_name=f"{process_name}_read",
        debug=settings.DEBUG,
        pool_size=settings.DATABASE_POOL_SIZE,
        pool_recycle=settings.DATABASE_POOL_RECYCLE_SECONDS,
    )


def create_sync_engine(process_name: ProcessName) -> Engine:
    """Create sync engine for migrations and scripts."""
    return _create_sync_engine(
        dsn=str(settings.get_postgres_dsn("psycopg2")),
        application_name=f"{settings.ENV.value}.{process_name}",
        pool_logging_name=f"{process_name}_sync",
        debug=settings.DEBUG,
        pool_size=settings.DATABASE_SYNC_POOL_SIZE,
        pool_recycle=settings.DATABASE_POOL_RECYCLE_SECONDS,
    )


class AsyncSessionMiddleware:
    """
    ASGI middleware that creates an async session per request
    and stores it in request.state
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        sessionmaker: AsyncSessionMaker = scope["state"]["async_sessionmaker"]
        async with sessionmaker() as session:
            scope["state"]["async_session"] = session
            await self.app(scope, receive, send)


async def get_db_session(request: Request) -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency - asycn write session with
    commit/rollback created by the middleware"""
    try:
        session: AsyncSession = request.state.async_session
    except AttributeError as e:
        raise RuntimeError(
            "Session is not present in the request state. "
            "Did you forget to add DBSessionMiddleware?"
        ) from e

    try:
        yield session
    except Exception:
        await session.rollback()
        raise
    else:
        await session.commit()


async def get_db_read_session(request: Request) -> AsyncGenerator[AsyncReadSession]:
    """ "FastAPI dependency - read-only session from the replica.
    Sessions are created per-call (no middleware), since read queries are
    typically short and don't need transaction management.
    """
    read_sessionmaker: AsyncReadSessionMaker = request.state.async_read_sessionmaker
    async with read_sessionmaker() as session:
        yield session


__all__ = [
    "AsyncEngine",
    "AsyncReadSession",
    "AsyncSession",
    "create_async_engine",
    "create_async_read_engine",
    "create_sync_engine",
    "get_db_session",
    "get_db_read_session",
    "AsyncSessionMiddleware",
]
