"""Database connection management."""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .models import Base


# Global engine and session factory
_engine = None
_async_session_factory = None


def _get_database_url(db_path: Optional[str] = None) -> str:
    """
    Get the SQLite database URL.

    Args:
        db_path: Path to the database file. If None, uses default.

    Returns:
        SQLAlchemy async database URL.
    """
    if db_path is None:
        db_path = os.getenv("DATABASE_PATH", "./data/settings.db")

    # Ensure directory exists
    db_dir = Path(db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    # Convert to absolute path for SQLite
    abs_path = Path(db_path).resolve()

    return f"sqlite+aiosqlite:///{abs_path}"


async def init_db(db_path: Optional[str] = None) -> None:
    """
    Initialize the database, creating tables if they don't exist.

    Args:
        db_path: Optional path to database file.
    """
    global _engine, _async_session_factory

    database_url = _get_database_url(db_path)

    _engine = create_async_engine(
        database_url,
        echo=False,  # Set to True for SQL debugging
        future=True,
    )

    # Enable foreign keys for SQLite
    @event.listens_for(_engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        cursor.close()

    _async_session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Create tables
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close the database connection."""
    global _engine, _async_session_factory

    if _engine:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get an async database session.

    Usage:
        async with get_db() as session:
            # Use session
            result = await session.execute(...)

    Yields:
        AsyncSession instance.

    Raises:
        RuntimeError: If database is not initialized.
    """
    if _async_session_factory is None:
        raise RuntimeError(
            "Database not initialized. Call init_db() first."
        )

    async with _async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for getting a database session.

    Usage in FastAPI:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db_session)):
            ...

    Yields:
        AsyncSession instance.
    """
    async with get_db() as session:
        yield session
