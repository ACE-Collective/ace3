"""Observable-detection settings router (ACE API v2)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security, status
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.util.observable_detection import InvalidDetectionValue
from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.detection import service
from aceapi_v2.detection.schemas import (
    DetectionCreate,
    DetectionPage,
    ExpirationUpdate,
    ObservableDetectionRead,
    ObservableTypeOptions,
)

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/", response_model=DetectionPage)
async def list_detections(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("detection", "read"))],
    search: str | None = None,
    observable_type: str | None = None,
    page: int = 1,
    page_size: int = service.DEFAULT_PAGE_SIZE,
) -> DetectionPage:
    return await service.get_detection_page(
        session,
        search=search, observable_type=observable_type,
        page=page, page_size=page_size,
    )


@router.get("/types", response_model=ObservableTypeOptions)
async def observable_types(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("detection", "read"))],
) -> ObservableTypeOptions:
    return ObservableTypeOptions(
        present=await service.list_present_types(session),
        all=service.list_all_observable_types(),
    )


@router.post("/", response_model=ObservableDetectionRead, status_code=status.HTTP_201_CREATED)
async def create_detection(
    body: DetectionCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("detection", "write"))],
) -> ObservableDetectionRead:
    detection_context = body.detection_context or f"manually added by {auth.auth_name}"

    try:
        return await service.create_detection(
            session,
            observable_type=body.type,
            value=body.value,
            created_by_user_id=auth.auth_user_id,
            detection_context=detection_context,
            expires_on=body.expires_on,
            batch_id=body.batch_id,
        )
    except InvalidDetectionValue as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except service.DetectionAlreadyExists as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.delete("/{detection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_detection(
    detection_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("detection", "write"))],
) -> None:
    if not await service.delete_detection(session, detection_id):
        raise HTTPException(status_code=404, detail="Detection not found")


@router.patch("/{detection_id}/expiration", response_model=ObservableDetectionRead)
async def set_expiration(
    detection_id: int,
    body: ExpirationUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("detection", "write"))],
) -> ObservableDetectionRead:
    result = await service.set_detection_expiration(
        session, detection_id, body.expires_on, auth.auth_user_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return result
