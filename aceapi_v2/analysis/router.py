"""Analysis router (ACE API v2).

Submitting analysis to this node: `ace_api.submit()` and everything built on it (`ace submit`,
`ace hunt --submit-alerts`, the GUI's New Alert, which sends to the node the analyst picks, and
other tools). Needs alert:create, which the automation key's scope includes.
"""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Security, UploadFile, status

from aceapi_v2.analysis import service
from aceapi_v2.analysis.schemas import SubmitResult
from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.sync import run_db_in_thread
from saq.logging import log_audit

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.post("/", response_model=SubmitResult, status_code=status.HTTP_201_CREATED)
async def submit(
    request: Request,
    analysis: Annotated[str, Form(description="the submission as a JSON object: description (required), "
                                              "analysis_mode, tool, tool_instance, type, event_time, event_time_source, "
                                              "details, "
                                              "observables, tags, queue, instructions, extensions, company_id")],
    auth: Annotated[ApiAuthResult, Depends(require_permission("alert", "create"))],
    file: Annotated[list[UploadFile] | None, File(description="files to add as file observables (repeat for more)")] = None,
) -> SubmitResult:
    """Create a root analysis from a submission and queue it on this node; in correlation mode it
    becomes an alert. 503 while the node is draining."""
    try:
        submission = json.loads(analysis)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"analysis is not JSON: {e}")
    if not isinstance(submission, dict):
        raise HTTPException(status_code=422, detail="analysis must be a JSON object")

    uploads = file or []
    remote_addr = request.client.host if request.client else "unknown"
    uuid = await run_db_in_thread(
        service.submit, submission, [(upload.filename, upload.file) for upload in uploads], remote_addr)
    log_audit("%s submitted %s (%s, %d files)", auth.auth_name, uuid,
              submission.get("analysis_mode") or "default mode", len(uploads), auth=auth, root_uuid=uuid)
    return SubmitResult(uuid=uuid)
