"""Observable type service for ACE API v2."""

import logging

from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.database import get_async_session
from aceapi_v2.sync import run_async
from saq.constants import VALID_OBSERVABLE_TYPES
from saq.database.model import Observable

logger = logging.getLogger(__name__)


async def get_observable_types(session: AsyncSession) -> list[str]:
    """Return a list of unique observable types from the database.

    Args:
        session: AsyncSession for database access

    Returns:
        List of observable type names, sorted alphabetically
    """
    result = await session.execute(select(distinct(Observable.type)))
    db_types = [row[0] for row in result.all()]
    all_types = set(db_types + VALID_OBSERVABLE_TYPES)

    return sorted(all_types)


def get_observable_types_sync() -> list[str]:
    """Synchronous wrapper for get_observable_types.

    Uses asyncio.run() to call the async service with a fresh async session.
    Falls back to the static VALID_OBSERVABLE_TYPES list on error.
    """
    
    async def _fetch():
        async for session in get_async_session():
            return await get_observable_types(session)

    try:
        return run_async(_fetch())
    except Exception as e:
        logger.warning("Failed to fetch observable types from database: %s", e)
        return sorted(VALID_OBSERVABLE_TYPES)
