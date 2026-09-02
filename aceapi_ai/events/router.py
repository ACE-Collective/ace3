"""ACE Event read for the AI investigation API.

One route, GET /events/{id}, behind its own ai:event permission: the event's metadata plus the
uuid and current version token of every alert mapped to it -- what investigation tooling needs
to keep a case in step with the ACE Event (status, disposition, owner, the cycle times, and which
alerts were added) without holding a key that reaches the main API. Reuses the aceapi_v2 event
service and response schema unchanged.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from aceapi_ai.audit import audit_event
from aceapi_ai.dependencies import get_current_auth
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import require_permission
from aceapi_v2.events import service
from aceapi_v2.events.schemas import EventRead

router = APIRouter()

_require_ai_event = require_permission("ai", "event", auth_dependency=get_current_auth)


@router.get("/{event_ref}", response_model=EventRead)
async def get_event(
    event_ref: str,
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_event)],
) -> EventRead:
    """Return one event by numeric id or uuid: its metadata, the UUIDs of its alerts (``alerts``),
    each alert's current version token (``alert_versions``) and database state (``alert_details``:
    insert_date, owner, owner_time, disposition, disposition_time, disposition_user). 400 for a
    malformed reference, 404 for an unknown one."""
    audit_event("event_read", auth, request, event_ref=event_ref)
    event = await service.get_event(event_ref)
    return EventRead.model_validate(event)
