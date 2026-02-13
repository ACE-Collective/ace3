"""Observable type router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.cache import TTLCache
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth
from aceapi_v2.observable_types import service
from aceapi_v2.observable_types.schemas import ObservableTypeRead
from aceapi_v2.schemas import ListResponse

# All routes in this router require authentication
router = APIRouter(dependencies=[Security(get_current_auth)])

_cache = TTLCache()


@router.get("/", response_model=ListResponse[ObservableTypeRead])
async def list_observable_types(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ListResponse[ObservableTypeRead]:
    """Return a list of unique observable types from the database.

    Requires authentication (API key or JWT token).
    """
    cached = _cache.get("observable_types")
    if cached is not None:
        _cache.set_cache_headers(response)
        return cached

    types = await service.get_observable_types(session)
    data = ListResponse(data=[ObservableTypeRead(name=t) for t in types])
    _cache.set("observable_types", data)
    _cache.set_cache_headers(response)
    return data
