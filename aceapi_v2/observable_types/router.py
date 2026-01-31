"""Observable type router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, Security
from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth
from aceapi_v2.observable_types.schemas import ObservableTypeRead
from aceapi_v2.schemas import ListResponse
from saq.database.model import Observable

# All routes in this router require authentication
router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/", response_model=ListResponse[ObservableTypeRead])
async def list_observable_types(
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ListResponse[ObservableTypeRead]:
    """Return a list of unique observable types from the database.

    Requires authentication (API key or JWT token).
    """
    result = await session.execute(
        select(distinct(Observable.type)).order_by(Observable.type)
    )
    return ListResponse(
        data=[ObservableTypeRead(name=row[0]) for row in result.all()]
    )
