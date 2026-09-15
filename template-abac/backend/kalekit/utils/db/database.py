from sqlalchemy import Engine
from sqlalchemy import create_engine as _create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy.ext.asyncio import (
    create_async_engine as _create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker


class AsyncReadSession(AsyncSession):
    """
    Marker subclass for sessions bound to the read replica.
    Prevents accidental writes by making intent explicit at the type elvel.
    """


type SessionMaker = sessionmaker[Session]

type AsyncSessionMaker = async_sessionmaker[AsyncSession]

type AsyncReadSessionMaker = async_sessionmaker[AsyncReadSession]


def create_sync_engine(
    *,
    dsn: str,
    application_name: str | None = None,
    debug: bool = False,
    pool_logging_name: str | None = None,
    pool_size: int | None = None,
    pool_recycle: int | None = None,
) -> Engine:
    return _create_engine(
        dsn,
        echo=debug,
        connect_args={"application_name": application_name} if application_name else {},
        pool_logging_name=pool_logging_name,
        pool_size=pool_size,
        pool_recycle=pool_recycle,
    )


def create_async_engine(
    *,
    dsn: str,
    application_name: str | None = None,
    debug: bool = False,
    pool_logging_name: str | None = None,
    pool_size: int | None = None,
    pool_recycle: int | None = None,
) -> AsyncEngine:
    return _create_async_engine(
        dsn,
        echo=debug,
        pool_logging_name=pool_logging_name,
        pool_size=pool_size,
        pool_recycle=pool_recycle,
        connect_args={
            "server_settings": {"application_name": application_name},
        },
    )


def create_sync_sessionmaker(engine: Engine) -> SessionMaker:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_async_sessionmaker(engine: AsyncEngine) -> AsyncSessionMaker:
    return async_sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_async_read_sessionmaker(engine: AsyncEngine) -> AsyncReadSessionMaker:
    return async_sessionmaker(
        bind=engine, class_=AsyncReadSession, autoflush=False, expire_on_commit=False
    )


__all__ = [
    "AsyncEngine",
    "AsyncReadSession",
    "AsyncReadSessionMaker",
    "AsyncSession",
    "AsyncSessionMaker",
    "Engine",
    "Session",
    "SessionMaker",
    "create_async_engine",
    "create_async_read_sessionmaker",
    "create_async_sessionmaker",
    "create_sync_engine",
    "create_sync_sessionmaker",
]
