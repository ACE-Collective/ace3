"""Saved filter router for ACE API v2.

Saved filters belong to a screen (saq/gui/filter_screens.py). The endpoints that list, create
or bound rows take ?screen= (default: alerts, the alert manage page); an unknown screen is a 404
and a filter that screen does not support is a 422. A row addressed by uuid carries its own.

Permission note: every endpoint, the writes included, requires the permission that reads the
screen's data (FilterScreen.permission: alert:read for the alert manage page, signature:read
for the SVS samples). A saved filter is per-user UI state whose entire content is something the
user could already type into the filter bar or a URL, so there is no deployment where you would
grant the read and deny "save a view". A row addressed by uuid is checked against its own
screen. The real access control here is row OWNERSHIP, enforced in the service.
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Security
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_screen_permission, screen_from_query
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
from saq.gui.filter_screens import FilterScreen, UnknownFilterScreen, get_filter_screen

router = APIRouter(dependencies=[Security(get_current_auth)])

NOT_OWNER = "This saved filter belongs to another user"

def _invalid_filters(e: ValidationError) -> HTTPException:
    """A filter the screen does not support, reported in FastAPI's own 422 shape."""
    return HTTPException(status_code=422, detail=e.errors(include_url=False, include_context=False))


def _unknown_screen(e: UnknownFilterScreen) -> HTTPException:
    return HTTPException(status_code=404, detail=str(e))


async def _screen_of_row(
    filter_uuid: str, session: Annotated[AsyncSession, Depends(get_async_session)]
) -> Optional[str]:
    """The screen of the row a uuid names, whoever owns it; None for an unknown row (the route
    answers 404)."""
    return await service.get_saved_filter_screen(session, filter_uuid)


# routes that take ?screen= need that screen's permission; routes that name a row by uuid need
# the permission of the row's own screen (aceapi_v2/dependencies.py, require_screen_permission)
SCREEN_GATE = [Depends(require_screen_permission(screen_from_query))]
ROW_GATE = [Depends(require_screen_permission(_screen_of_row))]

ScreenName = Annotated[Optional[str], Depends(screen_from_query)]


def _screen(name: str) -> FilterScreen:
    try:
        return get_filter_screen(name)
    except UnknownFilterScreen as e:
        raise _unknown_screen(e)


def _require_user(auth: ApiAuthResult) -> int:
    if auth.auth_user_id is None:
        raise HTTPException(status_code=401, detail="User authentication required")
    return auth.auth_user_id


@router.get("/", response_model=ListResponse[SavedFilterRead], dependencies=SCREEN_GATE)
async def list_saved_filters(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
    screen_name: ScreenName,
) -> ListResponse[SavedFilterRead]:
    filters = await service.get_saved_filters_for_user(session, _require_user(auth), screen=_screen(screen_name).name)
    return ListResponse(data=filters)


@router.get("/{filter_uuid}", response_model=SavedFilterRead, dependencies=ROW_GATE)
async def get_saved_filter(
    filter_uuid: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
) -> SavedFilterRead:
    saved_filter = await service.get_saved_filter(session, filter_uuid, _require_user(auth))
    if saved_filter is None:
        raise HTTPException(status_code=404, detail="Saved filter not found")
    return saved_filter


@router.post("/", response_model=SavedFilterRead, status_code=201, dependencies=SCREEN_GATE)
async def create_saved_filter(
    body: SavedFilterCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
    screen_name: ScreenName,
) -> SavedFilterRead:
    try:
        return await service.create_saved_filter(session, _require_user(auth), body, screen=_screen(screen_name).name)
    except ValidationError as e:
        raise _invalid_filters(e)
    except SavedFilterNameConflict as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.patch("/{filter_uuid}", response_model=SavedFilterRead, dependencies=ROW_GATE)
async def update_saved_filter(
    filter_uuid: str,
    body: SavedFilterUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
) -> SavedFilterRead:
    try:
        saved_filter = await service.update_saved_filter(session, filter_uuid, _require_user(auth), body)
    except PermissionError:
        raise HTTPException(status_code=403, detail=NOT_OWNER)
    except ValidationError as e:
        raise _invalid_filters(e)
    except SavedFilterNameConflict as e:
        raise HTTPException(status_code=409, detail=str(e))
    if saved_filter is None:
        raise HTTPException(status_code=404, detail="Saved filter not found")
    return saved_filter


@router.delete("/{filter_uuid}", status_code=204, dependencies=ROW_GATE)
async def delete_saved_filter(
    filter_uuid: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
) -> None:
    try:
        deleted = await service.delete_saved_filter(session, filter_uuid, _require_user(auth))
    except PermissionError:
        raise HTTPException(status_code=403, detail=NOT_OWNER)
    if not deleted:
        raise HTTPException(status_code=404, detail="Saved filter not found")


@router.put("/quick-filters", response_model=ListResponse[SavedFilterRead], dependencies=SCREEN_GATE)
async def set_quick_filters(
    body: QuickFilterOrder,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
    screen_name: ScreenName,
) -> ListResponse[SavedFilterRead]:
    """Set a screen's quick-filter membership and order together. Anything not listed is
    unpinned, so a reorder UI can submit its whole state and the call is idempotent."""
    try:
        filters = await service.set_quick_filters(session, _require_user(auth), body, screen=_screen(screen_name).name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return ListResponse(data=filters)


@router.put("/scratch/{kind}", response_model=SavedFilterRead, dependencies=SCREEN_GATE)
async def upsert_scratch_filter(
    kind: str,
    body: ScratchFilterWrite,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Security(get_current_auth)],
    screen_name: ScreenName,
) -> SavedFilterRead:
    """Replace the caller's singleton `working` (unsaved edits) or `temp` (active pivot)
    row on a screen. This is how ad-hoc filter state persists without going in the session
    cookie."""
    if kind not in SCRATCH_KINDS:
        raise HTTPException(status_code=404, detail=f"Unknown scratch kind {kind!r}")
    try:
        return await service.upsert_scratch_filter(session, _require_user(auth), kind, body, screen=_screen(screen_name).name)
    except ValidationError as e:
        raise _invalid_filters(e)
