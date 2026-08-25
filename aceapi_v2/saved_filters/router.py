"""Saved filter router for ACE API v2.

Permission note: every endpoint uses alert:read, including the writes. A saved filter is
per-user UI state whose entire content is something the analyst could already type into
the filter bar or a URL, so there is no deployment where you would grant alert:read and
deny "save a view". The real access control here is row OWNERSHIP, enforced in the service.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.saved_filters import service
from aceapi_v2.saved_filters.schemas import (
    QuickFilterOrder,
    SavedFilterCreate,
    SavedFilterRead,
    SavedFilterUpdate,
    ScratchFilterWrite,
)
from aceapi_v2.saved_filters.service import SCRATCH_KINDS, SavedFilterNameConflict
from aceapi_v2.schemas import ListResponse

router = APIRouter(dependencies=[Security(get_current_auth)])

NOT_OWNER = "This saved filter belongs to another user"


def _require_user(auth: ApiAuthResult) -> int:
    if auth.auth_user_id is None:
        raise HTTPException(status_code=401, detail="User authentication required")
    return auth.auth_user_id


@router.get("/", response_model=ListResponse[SavedFilterRead])
async def list_saved_filters(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> ListResponse[SavedFilterRead]:
    filters = await service.get_saved_filters_for_user(session, _require_user(auth))
    return ListResponse(data=filters)


@router.get("/{filter_uuid}", response_model=SavedFilterRead)
async def get_saved_filter(
    filter_uuid: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> SavedFilterRead:
    saved_filter = await service.get_saved_filter(session, filter_uuid, _require_user(auth))
    if saved_filter is None:
        raise HTTPException(status_code=404, detail="Saved filter not found")
    return saved_filter


@router.post("/", response_model=SavedFilterRead, status_code=201)
async def create_saved_filter(
    body: SavedFilterCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> SavedFilterRead:
    try:
        return await service.create_saved_filter(session, _require_user(auth), body)
    except SavedFilterNameConflict as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.patch("/{filter_uuid}", response_model=SavedFilterRead)
async def update_saved_filter(
    filter_uuid: str,
    body: SavedFilterUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> SavedFilterRead:
    try:
        saved_filter = await service.update_saved_filter(session, filter_uuid, _require_user(auth), body)
    except PermissionError:
        raise HTTPException(status_code=403, detail=NOT_OWNER)
    except SavedFilterNameConflict as e:
        raise HTTPException(status_code=409, detail=str(e))
    if saved_filter is None:
        raise HTTPException(status_code=404, detail="Saved filter not found")
    return saved_filter


@router.delete("/{filter_uuid}", status_code=204)
async def delete_saved_filter(
    filter_uuid: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> None:
    try:
        deleted = await service.delete_saved_filter(session, filter_uuid, _require_user(auth))
    except PermissionError:
        raise HTTPException(status_code=403, detail=NOT_OWNER)
    if not deleted:
        raise HTTPException(status_code=404, detail="Saved filter not found")


@router.put("/quick-filters", response_model=ListResponse[SavedFilterRead])
async def set_quick_filters(
    body: QuickFilterOrder,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> ListResponse[SavedFilterRead]:
    """Set quick-filter membership and order together. Anything not listed is unpinned, so
    a reorder UI can submit its whole state and the call is idempotent."""
    try:
        filters = await service.set_quick_filters(session, _require_user(auth), body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return ListResponse(data=filters)


@router.put("/scratch/{kind}", response_model=SavedFilterRead)
async def upsert_scratch_filter(
    kind: str,
    body: ScratchFilterWrite,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> SavedFilterRead:
    """Replace the caller's singleton `working` (unsaved edits) or `temp` (active pivot)
    row. This is how ad-hoc filter state persists without going in the session cookie."""
    if kind not in SCRATCH_KINDS:
        raise HTTPException(status_code=404, detail=f"Unknown scratch kind {kind!r}")
    return await service.upsert_scratch_filter(session, _require_user(auth), kind, body)
