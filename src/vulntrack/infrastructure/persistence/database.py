from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        from vulntrack.config import get_settings

        settings = get_settings()
        connect_args: dict[str, Any] = {}
        if "sqlite" in settings.database_url:
            connect_args = {"check_same_thread": False}
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            connect_args=connect_args,
        )
    return _engine


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
    return _session_factory


def get_engine() -> AsyncEngine:
    return _get_engine()


def AsyncSessionLocal() -> AsyncSession:
    """Retorna una sesión async usable como context manager (async with AsyncSessionLocal() as s:)."""
    return _get_session_factory()()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: provides one async session per request."""
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
