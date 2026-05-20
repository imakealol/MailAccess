from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import settings
from .models import Base

engine = create_async_engine(settings.database_url, echo=settings.debug)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


def _migrate_add_graph_data(sync_conn) -> None:
    """Add graph_data JSON column to investigations if missing (existing DBs)."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "graph_data" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN graph_data JSON")
        )


async def init_db() -> None:
    """Create all tables if they don't exist. Called once at app startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_migrate_add_graph_data)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a scoped async DB session."""
    async with AsyncSessionLocal() as session:
        yield session
