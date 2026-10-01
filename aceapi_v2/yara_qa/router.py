"""YARA QA results router for ACE API v2 (docs/YARA_QA.md).

A YARA rule with `modifiers = "qa"` is vetted against live data without alerting: every file it
matches is kept, up to a cap per rule version and per rule, for yara_qa.retention_days after it
last matched. These endpoints list the rules in QA mode (including ones that have not matched
anything yet) with their match counts, list what each one matched, and hand out the files.

Reading counts and match records needs signature:read. Anything that returns the matched files
needs signature:download: they are live malware, and they are served only inside zips encrypted
with the password 'infected'.
"""

import logging
import os
import shutil
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query, Security
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import ZIP_DOWNLOAD_RESPONSES, ZipFileResponse
from aceapi_v2.yara_qa import service
from aceapi_v2.yara_qa.schemas import QAMatch, QAMatchDetail, QAPage, QASignatureDetail, QASignaturePage
from saq.yara_qa.listing import QASort, QAStatus

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


def _safe_unlink(path: str) -> None:
    try:
        os.remove(path)
    except OSError as e:
        logger.warning("failed to remove temp file %s: %s", path, e)


def _safe_rmtree(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


@router.get("/", response_model=QASignaturePage)
async def list_signatures(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    q: Annotated[Optional[str], Query(description="substring of the rule name, uuid, namespace or file")] = None,
    status: Annotated[Optional[QAStatus], Query(description="qa (in QA mode now), not_qa (left QA mode) or missing (no longer loaded). Omit for all")] = None,
    has_matches: Annotated[Optional[bool], Query(description="only rules that have (true) or have not (false) matched")] = None,
    sort: Annotated[QASort, Query()] = QASort.NAME,
    descending: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> QASignaturePage:
    """List YARA rules in QA mode, and rules with recorded QA matches, with their match counts.

    Rules in QA mode that have never matched are included, with zero counts. ``match_count``
    counts every match, including those past the file cap; ``stored_count`` counts the files kept.
    """
    return await service.list_signatures(
        session, q=q, status=status, has_matches=has_matches, sort=sort, descending=descending,
        limit=limit, offset=offset)


# the /matches routes come before the /{signature_uuid} ones so "matches" is never read as a uuid

@router.get("/matches/{match_id}", response_model=QAMatchDetail)
async def get_match(
    match_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
) -> QAMatchDetail:
    """One stored match, with a summary of the match record (meta, tags, and per string how many
    times it matched and where first)."""
    return await service.get_match(session, match_id)


@router.get("/matches/{match_id}/record")
async def get_match_record(
    match_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
) -> FileResponse:
    """The full match record as the scanner produced it (application/json), never truncated.

    It can be large: a loose string can match thousands of times. It is read from the CAS, so a
    match stored on another node's local pool answers 409 wrong_node.
    """
    row = await service.resolve_record(session, match_id)
    path = await run_in_threadpool(service.materialize_record, row)
    return FileResponse(
        path,
        media_type="application/json",
        filename=f"yara-qa-match-{row.id}.json",
        # shown in the browser rather than saved (the GUI opens it in a tab). the record holds bytes
        # from the analyzed file, so the browser must never sniff it into anything but JSON
        content_disposition_type="inline",
        headers={"X-Content-Type-Options": "nosniff"},
        background=BackgroundTask(_safe_unlink, path),
    )


@router.get(
    "/matches/{match_id}/download",
    response_class=ZipFileResponse,
    responses=ZIP_DOWNLOAD_RESPONSES,
)
async def download_match(
    match_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "download"))],
) -> ZipFileResponse:
    """Download one matched file and its match record as a zip encrypted with password 'infected'."""
    row = await service.resolve_single_download(session, match_id)
    logger.info("AUDIT: user %s downloading yara qa match %s (signature %s, sha256 %s)",
                auth.auth_name, row.id, row.signature_uuid, row.sha256)
    label = f"yara-qa-match-{row.id}"
    zip_path, staging = await run_in_threadpool(service.create_encrypted_zip, label, [row], [], auth.auth_name)
    return ZipFileResponse(
        zip_path,
        # FileResponse ignores the class attribute; without this it guesses from the filename
        media_type="application/zip",
        filename=f"{label}.zip",
        background=BackgroundTask(_safe_rmtree, staging),
    )


@router.get("/{signature_uuid}", response_model=QASignatureDetail)
async def get_signature(
    signature_uuid: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
) -> QASignatureDetail:
    """One signature, with its counts per version, most recent first."""
    return await service.get_signature(session, signature_uuid)


@router.get("/{signature_uuid}/matches", response_model=QAPage[QAMatch])
async def list_matches(
    signature_uuid: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "read"))],
    version: Annotated[Optional[str], Query(description="only matches under this version of the rule")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> QAPage[QAMatch]:
    """The stored files of one signature, newest first. ``local`` says whether this node can
    serve the file."""
    return await service.list_matches(session, signature_uuid, version=version, limit=limit, offset=offset)


@router.get(
    "/{signature_uuid}/download",
    response_class=ZipFileResponse,
    responses=ZIP_DOWNLOAD_RESPONSES,
)
async def download_signature_matches(
    signature_uuid: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("signature", "download"))],
    version: Annotated[Optional[str], Query(description="only matches under this version of the rule")] = None,
    match_id: Annotated[list[int], Query(description="only these matches (repeat the parameter); every one must belong to this signature")] = [],
) -> ZipFileResponse:
    """Download stored files of one signature, with their match records and a manifest, as one
    zip encrypted with password 'infected'.

    Without match_id, every stored file of the signature (or of one version). Limited to
    yara_qa.max_bulk_download_files files and yara_qa.max_bulk_download_bytes bytes (413 past
    either). Files stored on another node's local pool are listed in the manifest under skipped.
    """
    rows, remote = await service.resolve_bulk_download(session, signature_uuid, version=version, match_ids=match_id)
    logger.info("AUDIT: user %s downloading %s yara qa matches of signature %s (version %s): %s",
                auth.auth_name, len(rows), signature_uuid, version or "all", [row.id for row in rows])
    label = f"yara-qa-{signature_uuid}"
    zip_path, staging = await run_in_threadpool(service.create_encrypted_zip, label, rows, remote, auth.auth_name)
    return ZipFileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"{label}.zip",
        background=BackgroundTask(_safe_rmtree, staging),
    )
