"""Observable router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security, status
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.observables import service
from aceapi_v2.observables.schemas import (
    ObservableLookupRequest,
    ObservableLookupResponse,
    SetInterestingRequest,
)
from saq.database.util.observable_detection import InvalidDetectionValue

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.patch("/interesting")
async def set_interesting(
    body: SetInterestingRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[None, Depends(require_permission("observable", "write"))],
) -> dict:
    try:
        await service.set_observable_interesting(
            session, body.observable_type, body.observable_value, body.is_interesting
        )
    except InvalidDetectionValue as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    status_text = "marked" if body.is_interesting else "unmarked"
    return {"message": f"Observable {status_text} as interesting"}


@router.post("/lookup", response_model=ObservableLookupResponse)
async def lookup_observables(
    body: ObservableLookupRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("observable", "read"))],
) -> ObservableLookupResponse:
    return await service.lookup_observables(
        session,
        pairs=body.observables,
        recent_alert_limit=body.recent_alert_limit,
        exclude_alert_uuids=body.exclude_alert_uuids,
        since=body.since,
    )
