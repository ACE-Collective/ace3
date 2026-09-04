"""Event router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from fastapi.responses import PlainTextResponse

from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.events import service
from aceapi_v2.events.schemas import EventRead, ExportFormat, StatusUpdate
from aceapi_v2.schemas.base import ListResponse

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/open", response_model=ListResponse[EventRead])
async def open_events(
    auth: Annotated[None, Depends(require_permission("event", "read"))],
) -> ListResponse[EventRead]:
    events = await service.get_open_events()
    return ListResponse(data=[EventRead.model_validate(e) for e in events])


@router.patch("/{event_id}", response_model=EventRead)
async def update_event_status(
    event_id: int,
    body: StatusUpdate,
    auth: Annotated[None, Depends(require_permission("event", "write"))],
) -> EventRead:
    event = await service.set_event_status(event_id, body.status)
    return EventRead.model_validate(event)


@router.get("/export")
async def export_events(
    auth: Annotated[None, Depends(require_permission("event", "read"))],
    type: ExportFormat = ExportFormat.csv,
    event_ids: Annotated[list[int], Query(alias="checked_events[]")] = [],
) -> PlainTextResponse:
    # ExportFormat currently only has csv; FastAPI rejects other values with 422.
    csv_text = await service.export_events_to_csv(event_ids)
    return PlainTextResponse(content=csv_text, media_type="text/csv")


# Declared after the static GET routes ("/open", "/export") so those paths are
# not captured by the {event_id} parameter.
@router.get("/{event_ref}", response_model=EventRead)
async def get_event(
    event_ref: str,
    auth: Annotated[None, Depends(require_permission("event", "read"))],
) -> EventRead:
    """Return one event by numeric id or uuid: its metadata, the UUIDs of its alerts
    (``alerts``), each alert's current version token (``alert_versions``, uuid -> version) and
    each alert's database state (``alert_details``: insert_date, owner, owner_time, disposition,
    disposition_time, disposition_user)."""
    event = await service.get_event(event_ref)
    return EventRead.model_validate(event)
