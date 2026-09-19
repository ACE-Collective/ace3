"""Analysis module crash report router for ACE API v2.

When an analysis module raises, hangs, or takes its worker process down with it, ACE writes a
crash report and logs a ``crash_id``. 

The intended path is: an analyst (or an alert that is missing a module's analysis) yields a
crash id, and ``GET /crashes/{crash_id}/download`` returns everything recorded about it --
the traceback or the stuck thread's stacks, the analysis tree, and the file the module died
on -- as one encrypted archive.
"""

import logging
import os
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query, Security
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.crashes import service
from aceapi_v2.crashes.schemas import CrashReportDetail, CrashReportSummary
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import ZIP_DOWNLOAD_RESPONSES, ZipFileResponse
from aceapi_v2.schemas import ListResponse
from saq.crash_report import CRASH_TYPES

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


@router.get("/", response_model=ListResponse[CrashReportSummary])
async def list_crash_reports(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("crash", "read"))],
    root_uuid: Annotated[Optional[str], Query(description="only crashes recorded while analyzing this root/alert uuid")] = None,
    module: Annotated[Optional[str], Query(description="module name (email_analyzer) or module path")] = None,
    crash_type: Annotated[Optional[str], Query(description=f"one of: {', '.join(CRASH_TYPES)}")] = None,
    node: Annotated[Optional[str], Query(description="only crashes recorded on this node")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ListResponse[CrashReportSummary]:
    """List crash reports, newest first.

    Lists across every node, since the index is cluster-wide, but only reports with
    ``local: true`` can be downloaded from this node -- the rest live on the disk of the node
    whose worker died.
    """
    return ListResponse(data=await service.list_crash_reports(
        session,
        root_uuid=root_uuid, module=module, crash_type=crash_type, node=node,
        limit=limit, offset=offset,
    ))


@router.get("/{crash_id}", response_model=CrashReportDetail)
async def get_crash_report(
    crash_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("crash", "read"))],
) -> CrashReportDetail:
    """Everything recorded about one crash, including an inventory of the report's files.

    A report with ``complete: false`` is one whose worker was killed while it was writing its
    own crash report. What made it to disk is still returned.
    """
    return await service.get_crash_report(session, crash_id)


@router.get(
    "/{crash_id}/download",
    response_class=ZipFileResponse,
    responses=ZIP_DOWNLOAD_RESPONSES,
)
async def download_crash_report(
    crash_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("crash", "read"))],
) -> ZipFileResponse:
    """Download the whole crash report as a zip encrypted with password 'infected'.

    Encrypted because the archive contains the file observable the module crashed on.
    """
    crash_dir = await service.resolve_downloadable_report(session, crash_id)
    logger.info("AUDIT: user %s downloading crash report %s", auth.auth_name, crash_id)
    zip_path = await run_in_threadpool(service.create_encrypted_crash_zip, crash_id, crash_dir)
    return ZipFileResponse(
        zip_path,
        # FileResponse ignores the class attribute; without this it guesses from the filename
        media_type="application/zip",
        filename=f"crash-{crash_id}.zip",
        background=BackgroundTask(_safe_unlink, zip_path),
    )
