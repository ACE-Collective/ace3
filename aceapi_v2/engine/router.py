"""Engine router (ACE API v2).

Node to node only: every caller is another ACE node, with the automation key, whose scope is
engine:* (etc/saq.default.yaml apikeys.automation). A node pulls a work target from the node that
holds it (download, then clear once it is copied), and pushes one to another node (upload: a
collector delivering a submission, a drain moving delayed analysis, `ace correlate` on a remote
node, storage redistribution).
"""

import logging
import os
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Security, UploadFile
from pydantic import ValidationError
from starlette.background import BackgroundTask

from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.engine import service
from aceapi_v2.engine.schemas import ClearResult, UploadModifiers, UploadResult
from aceapi_v2.responses import TarFileResponse
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


def _peer(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/download/{uuid}", response_class=TarFileResponse)
async def download(
    uuid: str,
    request: Request,
    _: Annotated[ApiAuthResult, Depends(require_permission("engine", "download"))],
) -> TarFileResponse:
    """The work target's storage directory as a tar archive, for a node taking the work over."""
    path = await run_db_in_thread(service.create_download_tar, uuid)
    logger.info("sending work target %s to %s", uuid, _peer(request))
    # FileResponse ignores the class attribute; without this it guesses from the filename
    return TarFileResponse(path, media_type="application/x-tar", background=BackgroundTask(_safe_unlink, path))


@router.post("/upload/{uuid}", response_model=UploadResult)
async def upload(
    uuid: str,
    request: Request,
    archive: Annotated[UploadFile, File(description="the work target's storage directory as a tar archive")],
    upload_modifiers: Annotated[str, Form(description="UploadModifiers as a JSON object")],
    _: Annotated[ApiAuthResult, Depends(require_permission("engine", "upload"))],
) -> UploadResult:
    """Take over a work target pushed from another node. 409 when its storage directory already
    exists here and overwrite is not set."""
    try:
        modifiers = UploadModifiers.model_validate_json(upload_modifiers)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors(include_url=False, include_context=False))

    logger.info("receiving work target %s from %s (%s)", uuid, _peer(request), modifiers)
    storage_dir = await run_db_in_thread(service.receive_upload, uuid, archive.file, modifiers)
    return UploadResult(result=True, storage_dir=storage_dir)


@router.post("/clear/{uuid}/{lock_uuid}", response_model=ClearResult)
async def clear(
    uuid: str,
    lock_uuid: str,
    request: Request,
    _: Annotated[ApiAuthResult, Depends(require_permission("engine", "clear"))],
) -> ClearResult:
    """Delete this node's copy of a work target that another node has taken over. The lock_uuid
    must be the lock the caller holds on it (409 otherwise)."""
    await run_db_in_thread(service.clear_target, uuid, lock_uuid)
    logger.info("cleared work target %s for %s", uuid, _peer(request))
    return ClearResult(result=True)
