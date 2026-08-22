"""Alert package download for the AI investigation API.

Reuses the aceapi_v2 zip service but sits behind its own ai:alert permission, so an AI key's scope
never has to leave the ai: major -- a key misrouted to the main app passes nothing there.
"""

import logging
import os
from typing import Annotated

from fastapi import APIRouter, Depends, Request
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
