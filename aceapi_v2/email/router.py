"""Archived email router for ACE API v2."""

import logging
import shutil
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Security, status
from starlette.background import BackgroundTask

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.email import service
from aceapi_v2.email.schemas import SHA256_PATTERN, ArchiveLookupResponse, MessageIdsRequest
from aceapi_v2.responses import ZIP_DOWNLOAD_RESPONSES, Rfc822StreamResponse, ZipFileResponse
from aceapi_v2.sync import run_db_in_thread
from saq.logging import log_audit

logger = logging.getLogger(__name__)

# the zip's file name and its top-level directory
DOWNLOAD_LABEL = "archived-emails"

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/archive", response_class=Rfc822StreamResponse)
async def get_archived_email(
    message_id: str,
    _: Annotated[ApiAuthResult, Depends(require_permission("email", "read"))],
) -> Rfc822StreamResponse:
    """Stream the original of an archived email, decrypted, looked up by its Message-ID.

    The Message-ID is a query parameter rather than a path segment because Message-IDs can contain
    a "/".
    """
    try:
        content = await service.open_archived_email(message_id)
    except service.EncryptionKeyMissing as e:
        raise _no_encryption_key(f"archived email {message_id}", e) from e

    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"no archived email has message id {message_id}")

    return Rfc822StreamResponse(content)


def _no_encryption_key(what: str, error: service.EncryptionKeyMissing) -> HTTPException:
    # with the exception, so the error report handler writes a report and emits the monitor event
    logger.critical("%s requested but no encryption key is configured", what, exc_info=error)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="archived emails cannot be decrypted: no encryption key is configured",
    )


@router.post("/archive/lookup", response_model=ArchiveLookupResponse)
async def lookup_archived_emails(
    body: MessageIdsRequest,
    _: Annotated[ApiAuthResult, Depends(require_permission("email", "read"))],
) -> ArchiveLookupResponse:
    """Every archived email of each Message-ID, newest first, in request order: its sha256 (for
    GET /email/archive/{sha256}), when it was archived and its size. An email is archived for 30
    days after it was last archived (docs/EMAIL_ARCHIVE.md)."""
    return ArchiveLookupResponse(results=await run_db_in_thread(service.lookup_archived_emails, body.message_ids))


@router.get("/archive/{sha256}", response_class=Rfc822StreamResponse)
async def get_archived_email_copy(
    sha256: Annotated[str, Path(pattern=SHA256_PATTERN, description="the email's sha256, from POST /email/archive/lookup")],
    auth: Annotated[ApiAuthResult, Depends(require_permission("email", "read"))],
) -> Rfc822StreamResponse:
    """Stream one archived email, decrypted and unchanged, by its sha256: any copy of a Message-ID,
    not only the newest that GET /email/archive?message_id= returns."""
    try:
        content = await service.open_archived_copy(sha256)
    except service.EncryptionKeyMissing as e:
        raise _no_encryption_key(f"archived email {sha256}", e) from e

    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"no archived email has sha256 {sha256}")

    log_audit("user %s downloading archived email %s", auth.auth_name, sha256, auth=auth, sha256=sha256)
    return Rfc822StreamResponse(content, headers={"Content-Disposition": f'attachment; filename="{sha256}.eml"'})


@router.post("/archive/download", response_class=ZipFileResponse, responses=ZIP_DOWNLOAD_RESPONSES)
async def download_archived_emails(
    body: MessageIdsRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("email", "read"))],
) -> ZipFileResponse:
    """Download every archived email of each Message-ID, with a manifest, as one zip encrypted with
    password 'infected'.

    Each Message-ID's emails are in a directory of their own. The manifest lists them, and every
    Message-ID it has no email for, with why. Limited to email_archive.max_bulk_download_files
    emails and email_archive.max_bulk_download_bytes bytes (413 past either)."""
    try:
        service.require_encryption_key()
    except service.EncryptionKeyMissing as e:
        raise _no_encryption_key(f"a download of {len(body.message_ids)} archived emails", e) from e

    download = await run_db_in_thread(service.resolve_download, body.message_ids)
    log_audit("user %s downloading %s archived emails of %s message ids", auth.auth_name, len(download.sha256s),
              len(body.message_ids), auth=auth, sha256s=download.sha256s)
    zip_path, staging = await run_db_in_thread(service.create_download_zip, DOWNLOAD_LABEL, download, auth.auth_name)
    return ZipFileResponse(
        zip_path,
        # FileResponse ignores the class attribute; without this it guesses from the filename
        media_type="application/zip",
        filename=f"{DOWNLOAD_LABEL}.zip",
        background=BackgroundTask(shutil.rmtree, staging, ignore_errors=True),
    )
