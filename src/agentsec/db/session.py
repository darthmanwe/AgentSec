"""Async engine and session management (AS-005)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentsec.config import Settings

_ECHO_DEFAULT = False


def create_engine(settings: Settings, *, echo: bool = _ECHO_DEFAULT) -> AsyncEngine:
    """Build an async engine from settings.

    ``echo`` is off by default and should stay off outside interactive debugging: SQLAlchemy
    echo writes bound parameters, which for this schema includes argument payloads that may
    carry attacker-controlled content, and it bypasses the AS-003 redactor entirely.
    """
    return create_async_engine(
        settings.database_url.get_secret_value(),
        echo=echo,
        pool_pre_ping=True,
        future=True,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """A transactional scope that rolls back on error.

    Explicit rather than implicit: a half-written audit trail is worse than a missing one,
    because it looks complete.
    """
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


__all__ = ["create_engine", "create_session_factory", "session_scope"]
