"""Remediation router (ACE API v2).

The alert pages' remediation dialog: the remediation targets of the selected alerts, queueing a
removal or a restore of them, and stopping or clearing a target's latest remediation.

The Remediations page: the list of remediations with its filters (the remediations filter screen)
and exports, a remediation's history, and retrying, restoring, stopping and deleting one; adding
remediations is a lookup of the targets of observables, then queueing them.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security, status

from aceapi_v2 import listing
from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.remediation import service
from aceapi_v2.remediation.schemas import (
    REMEDIATION_ROW_CSV_FIELDS,
    QueueRemediationsRequest,
    RemediationHistoryEntry,
    RemediationListPage,
    RemediationSummary,
    RemediationTargetRead,
    TargetLookupRequest,
)
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.schemas.base import ListResponse
from aceapi_v2.sync import run_db_in_thread
from saq.gui.filter_screens import REMEDIATIONS_SCREEN
from saq.logging import log_audit

router = APIRouter(dependencies=[Security(get_current_auth)])

FilterParam = listing.filter_param(REMEDIATIONS_SCREEN)


def _user_id(auth: ApiAuthResult) -> int:
    # a remediation is attributed to the analyst who asked for it
    if auth.auth_user_id is None:
        raise HTTPException(status_code=400, detail="remediating needs a caller that is a user")
    return auth.auth_user_id


@router.post("/targets/lookup", response_model=ListResponse[RemediationTargetRead])
async def lookup_targets(
    body: TargetLookupRequest,
    _: Annotated[ApiAuthResult, Depends(require_permission("remediation", "read"))],
) -> ListResponse[RemediationTargetRead]:
    """The remediation targets of the observables in these alerts, or of these observables, each
    with its latest remediation.

    A POST so that a long selection fits in the body. Each alert's analysis is loaded from disk.
    An observable value its type rejects is a 422."""
    if body.alert_uuids:
        return ListResponse(data=await run_db_in_thread(service.lookup_targets, body.alert_uuids))

    return ListResponse(data=await run_db_in_thread(service.lookup_observable_targets, body.observables))


#
# the list and its exports
#

@router.get("/remediations", response_model=RemediationListPage)
@router.get("/remediations/", response_model=RemediationListPage, include_in_schema=False)
async def list_remediations(
    _: Annotated[ApiAuthResult, Depends(require_permission("remediation", "read"))],
    f: FilterParam,
    cursor: listing.CursorParam = None,
    limit: listing.LimitParam = 100,
    tz: listing.TimezoneParam = "UTC",
) -> RemediationListPage:
    """List remediations, newest first. Follow next_cursor, with the same filters, until it is null."""
    selection = service.prepare_listing(f, listing.timezone(tz))
    rows, next_cursor = await run_db_in_thread(listing.fetch_page, selection, cursor, limit)
    return RemediationListPage(data=rows, next_cursor=next_cursor)


@router.get("/remediations/export/ndjson", response_class=NdjsonStreamResponse)
async def export_remediations_ndjson(
    _: Annotated[ApiAuthResult, Depends(require_permission("remediation", "read"))],
    f: FilterParam,
    tz: listing.TimezoneParam = "UTC",
) -> NdjsonStreamResponse:
    """Stream every remediation the filters match as NDJSON, one RemediationRow per line; a failure
    part-way ends the stream with an {"error": ...} line."""
    return await listing.export_ndjson(service.prepare_listing(f, listing.timezone(tz)), "remediations.ndjson")


@router.get("/remediations/export/csv", response_class=CsvStreamResponse)
async def export_remediations_csv(
    _: Annotated[ApiAuthResult, Depends(require_permission("remediation", "read"))],
    f: FilterParam,
    tz: listing.TimezoneParam = "UTC",
) -> CsvStreamResponse:
    """Stream every remediation the filters match as CSV; a failure part-way truncates it."""
    return await listing.export_csv(
        service.prepare_listing(f, listing.timezone(tz)), REMEDIATION_ROW_CSV_FIELDS, "remediations.csv")


@router.get("/remediations/{remediation_id}/history", response_model=ListResponse[RemediationHistoryEntry])
async def get_remediation_history(
    remediation_id: int,
    _: Annotated[ApiAuthResult, Depends(require_permission("remediation", "read"))],
    limit: Annotated[int, Query(ge=1, le=1000, description="at most this many of the latest attempts")] = 100,
) -> ListResponse[RemediationHistoryEntry]:
    """What the remediation service recorded of each attempt at a remediation, newest first."""
    return ListResponse(data=await run_db_in_thread(service.history, remediation_id, limit))


@router.post("/remediations", response_model=ListResponse[RemediationSummary], status_code=status.HTTP_201_CREATED)
async def queue_remediations(
    body: QueueRemediationsRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> ListResponse[RemediationSummary]:
    """Queues a removal or a restore of each target for the remediation service. Every target is
    checked before any is queued."""
    queued = await run_db_in_thread(service.queue_remediations, body.action, body.targets, _user_id(auth))
    log_audit("user %s queued %s remediations %s for %s", auth.auth_name, body.action.value,
              ",".join(str(remediation.id) for remediation in queued),
              ", ".join(f"{t.remediator} {t.observable_type} {t.observable_value!r}" for t in body.targets),
              auth=auth, remediation_ids=[remediation.id for remediation in queued])
    return ListResponse(data=queued)


@router.post("/remediations/{remediation_id}/cancel", response_model=RemediationSummary)
async def cancel_remediation(
    remediation_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> RemediationSummary:
    """Stops a remediation that is queued or in progress. One that has completed is a 409: its
    result stands."""
    cancelled = await run_db_in_thread(service.cancel, remediation_id, _user_id(auth))
    log_audit("user %s cancelled remediation %s", auth.auth_name, remediation_id, auth=auth,
              remediation_id=remediation_id)
    return cancelled


@router.post("/remediations/{remediation_id}/retry", response_model=RemediationSummary)
async def retry_remediation(
    remediation_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> RemediationSummary:
    """Queues a completed remediation again, as it was. One that has not completed is a 409."""
    retried = await run_db_in_thread(service.retry, remediation_id)
    log_audit("user %s retried remediation %s", auth.auth_name, remediation_id, auth=auth,
              remediation_id=remediation_id)
    return retried


@router.post("/remediations/{remediation_id}/restore", response_model=RemediationSummary,
             status_code=status.HTTP_201_CREATED)
async def restore_remediation(
    remediation_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> RemediationSummary:
    """Queues a restore of what a successful removal removed, with the restore key that removal
    produced, and returns the restore. Anything but a removal that succeeded is a 409."""
    queued = await run_db_in_thread(service.restore, remediation_id, _user_id(auth))
    log_audit("user %s queued restore %s of remediation %s", auth.auth_name, queued.id, remediation_id, auth=auth,
              remediation_id=remediation_id, restore_id=queued.id)
    return queued


@router.delete("/remediations/{remediation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_remediation(
    remediation_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> None:
    """Deletes a remediation's record."""
    removed = await run_db_in_thread(service.delete, remediation_id)
    log_audit("user %s deleted remediation %s (%s, %s)", auth.auth_name, remediation_id,
              removed.action, removed.result or removed.status, auth=auth, remediation_id=remediation_id)
