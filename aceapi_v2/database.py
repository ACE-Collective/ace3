from collections.abc import AsyncGenerator
from urllib.parse import quote_plus

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from saq.configuration import get_config


def build_database_url(db_name: str = "ace") -> str:
    """Build async SQLAlchemy database URL from config."""
    db_config = get_config().get_database_config(db_name)
    # URL-encode password in case it contains special characters
    password = quote_plus(db_config.password)
    return f"mysql+aiomysql://{db_config.username}:{password}@{db_config.hostname}:{db_config.port}/{db_config.database}"


# Lazy-initialized engine and session maker (config may not be loaded at module import time)
_engine: AsyncEngine | None = None
_async_session_maker: async_sessionmaker | None = None


def _get_engine() -> AsyncEngine:
    """Get or create the async engine."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            build_database_url("ace"),
            echo=False,
            pool_pre_ping=True,
        )
    return _engine


def _get_session_maker() -> async_sessionmaker:
    """Get or create the async session maker."""
    global _async_session_maker
    if _async_session_maker is None:
        _async_session_maker = async_sessionmaker[AsyncSession](
            _get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return _async_session_maker


async def get_async_session() -> AsyncGenerator[AsyncSession]:
    async with _get_session_maker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
