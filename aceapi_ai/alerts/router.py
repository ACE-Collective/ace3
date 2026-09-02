"""Alert reads for the AI investigation API: the alert itself (with its version token as an ETag),
its saq.log, and the encrypted package download.

Reuses the aceapi_v2 alert service but sits behind its own ai:alert permission, so an AI key's scope
never has to leave the ai: major -- a key misrouted to the main app passes nothing there. Together
with /events these are the reads investigation tooling needs to keep a case in step with ACE
without ever holding a key that reaches the main API.
"""

import logging
import os
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from aceapi_ai.audit import audit_event
from aceapi_ai.dependencies import get_current_auth
from aceapi_v2.alerts import service
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import require_permission
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter()

_require_ai_alert = require_permission("ai", "alert", auth_dependency=get_current_auth)


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


@router.get(
    "/{alert_uuid}",
    responses={
        200: {"description": "The alert as {\"result\": {...}}; ETag header carries the version token."},
        304: {"description": "If-None-Match matched the current version; the alert has not changed."},
    },
)
async def get_alert(
    alert_uuid: str,
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_alert)],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    """Return the full alert (analysis tree plus database state) with its version token as the ETag.

    The same contract as GET /api/v2/alerts/{uuid}: the token changes whenever anything about the
    alert changes, so a client polls with If-None-Match and gets a 304 without the alert being loaded.
    """
    version = await run_db_in_thread(service.get_alert_version, alert_uuid)
    if if_none_match and service.etag_matches(if_none_match, version):
        audit_event("alert_version", auth, request, alert_uuid=alert_uuid, status=304)
        return Response(status_code=304, headers={"ETag": service.etag(version)})

    audit_event("alert_read", auth, request, alert_uuid=alert_uuid)
    body, version = await run_db_in_thread(service.get_alert, alert_uuid)
    return Response(content=body, media_type="application/json", headers={"ETag": service.etag(version)})


@router.get("/{alert_uuid}/logs")
async def view_alert_logs(
    alert_uuid: str,
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_alert)],
) -> FileResponse:
    """Return the alert's raw saq.log as text/plain."""
    audit_event("alert_logs", auth, request, alert_uuid=alert_uuid)
    log_path = await run_db_in_thread(service.resolve_alert_log_path, alert_uuid)
    return FileResponse(log_path, media_type="text/plain; charset=utf-8", content_disposition_type="inline")


@router.get("/{alert_uuid}/download")
async def download_alert(
    alert_uuid: str,
    request: Request,
    auth: Annotated[ApiAuthResult, Depends(_require_ai_alert)],
) -> FileResponse:
    """Download the full alert storage directory as a zip encrypted with password 'infected'."""
    audit_event("alert_download", auth, request, alert_uuid=alert_uuid)
    zip_path = await run_db_in_thread(service.create_encrypted_alert_zip, alert_uuid)
    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"{alert_uuid}.zip",
        background=BackgroundTask(_safe_unlink, zip_path),
    )
