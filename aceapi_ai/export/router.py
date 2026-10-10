"""Bulk export for the AI investigation API: every alert's database state with the ids of its
observables, its detections and its events, and the observable values those ids resolve to.

For offline analysis of the alert history -- how an observable has been dispositioned across
every alert it appeared in, including the archived ones the alert reads return 410 for. Behind
its own ai:export permission, because a key that can read every observable value ACE has seen
is a different grant from one that can search, and in its own rate-limit bucket
(ai_api.export_limits). Every page is audited.

A client pulls GET /export/alerts until next_cursor is null, then resolves the observable ids it
has not seen yet with POST /export/observables. Later pulls pass changed_since (see
aceapi_ai/export/service.py for why to resume a few minutes before the newest updated_at seen).
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from aceapi_ai.dependencies import get_current_auth
from aceapi_ai.export import service
from aceapi_ai.export.schemas import (
    MAX_ALERT_PAGE_SIZE,
    AlertExportPage,
    ObservableExportPage,
    ObservableExportRequest,
)
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import require_permission

router = APIRouter()

_require_ai_export = require_permission("ai", "export", auth_dependency=get_current_auth)


@router.get("/alerts", response_model=AlertExportPage)
async def export_alerts(
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_export)],
    changed_since: Annotated[datetime | None, Query(
        description="only alerts whose row changed at or after this time (UTC if no offset is "
                    "given), ordered by (updated_at, id) instead of id. At-least-once: resuming "
                    "from the last updated_at seen may repeat an alert, never skip one.")] = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_ALERT_PAGE_SIZE)] = MAX_ALERT_PAGE_SIZE,
) -> AlertExportPage:
    """Every alert this node shows, archived ones included, one keyset page at a time: the alert's
    row, its disposition class and review, and the ids of its observables, its detections and its
    events. 400 for a malformed cursor or one from a listing in another order."""
    return await service.export_alerts(changed_since, cursor, limit, auth, request)


@router.post("/observables", response_model=ObservableExportPage)
async def export_observables(
    body: ObservableExportRequest,
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_export)],
) -> ObservableExportPage:
    """The type, sha256 and value of each requested observable id, in id order."""
    return await service.export_observables(body, auth, request)
