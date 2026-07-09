"""Observable-detection settings router (ACE API v2)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.detection import service
from aceapi_v2.detection.schemas import (
    DetectionUpdate,
    ExpirationUpdate,
    ObservableDetectionRead,
    ObservablePage,
)

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/", response_model=ObservablePage)
async def list_observables(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("detection", "read"))],
    for_detection: bool | None = None,
    search: str | None = None,
    observable_type: str | None = None,
    page: int = 1,
    page_size: int = service.DEFAULT_PAGE_SIZE,
) -> ObservablePage:
    return await service.get_detection_page(
        session,
        for_detection=for_detection, search=search, observable_type=observable_type,
        page=page, page_size=page_size,
    )


@router.get("/types", response_model=list[str])
async def observable_types(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("detection", "read"))],
) -> list[str]:
    return await service.list_observable_types(session)


@router.patch("/{observable_id}/detection", response_model=ObservableDetectionRead)
async def set_detection(
    observable_id: int,
    body: DetectionUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("detection", "write"))],
) -> ObservableDetectionRead:
    result = await service.set_observable_for_detection(
        session, observable_id, body.enabled, auth.auth_user_id, body.detection_context
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Observable not found")
    return result


@router.patch("/{observable_id}/expiration", response_model=ObservableDetectionRead)
async def set_expiration(
    observable_id: int,
    body: ExpirationUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("detection", "write"))],
) -> ObservableDetectionRead:
    result = await service.set_observable_expiration(session, observable_id, body.expires_on)
    if result is None:
        raise HTTPException(status_code=404, detail="Observable not found")
    return result
