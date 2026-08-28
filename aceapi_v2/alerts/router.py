"""Alert router for ACE API v2."""

import logging
import os
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response, Security
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.sync import run_db_in_thread
from aceapi_v2.alerts import service
from aceapi_v2.alerts.schemas import BulkAddObservableRequest, BulkAddObservableResult

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


def _etag(version: str) -> str:
    return f'"{version}"'


def _etag_matches(if_none_match: str, version: str) -> bool:
    """True if the If-None-Match header names the given version (or is the wildcard)."""
    for candidate in if_none_match.split(","):
        candidate = candidate.strip()
        if candidate == "*":
            return True
        candidate = candidate.removeprefix("W/")
        if candidate.strip('"') == version:
            return True
    return False


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


@router.post("/bulk-add-observable", response_model=BulkAddObservableResult)
async def bulk_add_observable(
    body: BulkAddObservableRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "write"))],
) -> BulkAddObservableResult:
    """Add an observable to multiple alerts at once."""
    if not body.alert_uuids:
        raise HTTPException(status_code=400, detail="No alert UUIDs provided")

    if not body.observable_value:
        raise HTTPException(status_code=400, detail="Missing observable value")

    # Parse time if provided
    o_time = None
    if body.observable_time:
        try:
            o_time = datetime.strptime(body.observable_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid time format. Expected YYYY-MM-DD HH:MM:SS",
            )

    return await service.bulk_add_observable(
        alert_uuids=body.alert_uuids,
        o_type=body.observable_type,
        o_value=body.observable_value,
        o_time=o_time,
        directives=body.directives,
        username=auth.auth_name or "unknown",
    )


@router.get(
    "/{alert_uuid}",
    responses={
        200: {"description": "The alert as {\"result\": {...}}; ETag header carries the version token."},
        304: {"description": "If-None-Match matched the current version; the alert has not changed."},
    },
)
async def get_alert(
    alert_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    """Return the full alert: the analysis tree plus its database state.

    The alert's version token is returned both as the ETag header and as the
    `version` key of the result. It changes whenever anything about the alert
    changes (analysis, observables, comments, disposition, ownership, events), so a
    client can poll with If-None-Match and get a 304 without the alert being loaded.
    """
    version = await run_db_in_thread(service.get_alert_version, alert_uuid)
    if if_none_match and _etag_matches(if_none_match, version):
        return Response(status_code=304, headers={"ETag": _etag(version)})

    # the token comes from the loaded row, so the header always agrees with the body
    body, version = await run_db_in_thread(service.get_alert, alert_uuid)
    return Response(content=body, media_type="application/json", headers={"ETag": _etag(version)})


@router.get("/{alert_uuid}/download")
async def download_alert(
    alert_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
) -> FileResponse:
    """Download the full alert storage directory as a zip encrypted with password 'infected'."""
    logger.info("AUDIT: user %s downloading alert %s", auth.auth_name, alert_uuid)
    zip_path = await run_db_in_thread(service.create_encrypted_alert_zip, alert_uuid)
    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"{alert_uuid}.zip",
        background=BackgroundTask(_safe_unlink, zip_path),
    )


@router.get("/{alert_uuid}/logs")
async def view_alert_logs(
    alert_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "read"))],
    download: bool = False,
) -> FileResponse:
    """Return the alert's raw saq.log file.

    Default: text/plain with inline disposition (renders in browser).
    With ?download=true, served as an attachment download.
    """
    log_path = await run_db_in_thread(service.resolve_alert_log_path, alert_uuid)
    if download:
        return FileResponse(
            log_path,
            media_type="text/plain",
            filename=f"{alert_uuid}-saq.log",
        )
    return FileResponse(
        log_path,
        media_type="text/plain; charset=utf-8",
        content_disposition_type="inline",
    )
