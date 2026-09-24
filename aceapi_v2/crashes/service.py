"""Service layer for the analysis module crash report API.

Two data sources, with a deliberate split of responsibility:

* the **database index** (``analysis_module_crashes``) answers "which crashes exist" -- it is
  what makes listing and filtering possible, and it records which node a report is on.
* the **report directory on disk** answers "what does this crash report contain" -- it is
  authoritative, and it is what gets zipped and sent.

The index row is best effort at write time (see saq/crash_report.py), so every read path here
falls back to the filesystem: a crash id with no row is still fetchable and still downloadable.
The one thing that degrades without a row is the listing.
"""

import logging
import os
import tempfile
from datetime import datetime
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from starlette.concurrency import run_in_threadpool

from aceapi_v2.common.archive import add_to_encrypted_zip, remove_stale
from aceapi_v2.crashes.schemas import CrashReportDetail, CrashReportSummary
from saq.crash_replication import (
    fetch_metadata,
    fetch_report,
    remote_file_sizes,
    remote_report_exists,
    replication_enabled,
)
from saq.crash_report import (
    METADATA_FILE,
    find_crash_report_dir,
    is_valid_crash_id,
    list_report_files,
    read_crash_report,
)
from saq.database.model import AnalysisModuleCrash
from saq.environment import get_global_runtime_settings, get_temp_dir

logger = logging.getLogger(__name__)


def _local_node() -> Optional[str]:
    return get_global_runtime_settings().saq_node


def _validate_crash_id(crash_id: str) -> None:
    """Reject anything that is not a crash id before it is ever turned into a path.

    This endpoint builds a filesystem path out of a URL parameter and then serves the result to
    an analyst as an archive of live malware, so the check is at the boundary and unconditional.
    """
    if not is_valid_crash_id(crash_id):
        raise HTTPException(status_code=400, detail="invalid crash id")


def _row_to_summary(row: AnalysisModuleCrash, local_node: Optional[str], replicating: bool) -> CrashReportSummary:
    """One listing row.

    ``local`` means "downloadable from this node". With replication off that is the same thing as
    "written here"; with it on, every replicated report is reachable from everywhere, so the two
    stop being the same and ``node`` is what carries origin.
    """
    return CrashReportSummary(
        crash_id=row.uuid,
        crash_type=row.crash_type,
        insert_date=row.insert_date.isoformat() if row.insert_date else None,
        node=row.node,
        module_path=row.module_path,
        module_name=row.module_name,
        analysis_mode=row.analysis_mode,
        root_uuid=row.root_uuid,
        observable_type=row.observable_type,
        observable_value=row.observable_value,
        exception_type=row.exception_type,
        exception_message=row.exception_message,
        has_file=bool(row.has_file),
        local=replicating or row.node == local_node,
    )


async def list_crash_reports(
    session: AsyncSession,
    *,
    root_uuid: Optional[str] = None,
    module: Optional[str] = None,
    crash_type: Optional[str] = None,
    node: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CrashReportSummary]:
    """Crash reports newest first, filtered.

    Lists across all nodes -- the index is cluster-wide -- and marks each row with whether it can
    be downloaded from *this* node. With crash_reporting.replicate on that is every row; with it
    off, only the ones written here, and the rest say which node to ask.
    """
    query = select(AnalysisModuleCrash)

    if root_uuid:
        query = query.where(AnalysisModuleCrash.root_uuid == root_uuid)
    if module:
        # matches either the config name (email_analyzer) or the module path, since the log line
        # and the alert page give an analyst different ones of those
        query = query.where(
            (AnalysisModuleCrash.module_name == module)
            | (AnalysisModuleCrash.module_path == module)
        )
    if crash_type:
        query = query.where(AnalysisModuleCrash.crash_type == crash_type)
    if node:
        query = query.where(AnalysisModuleCrash.node == node)

    query = query.order_by(AnalysisModuleCrash.insert_date.desc(), AnalysisModuleCrash.id.desc())
    query = query.limit(limit).offset(offset)

    rows = (await session.execute(query)).scalars().all()
    local_node = _local_node()
    # one config read for the whole page rather than per row; a per-row existence check against
    # the object store would be one round trip per listed crash, which is not worth it for a flag
    replicating = replication_enabled()
    return [_row_to_summary(row, local_node, replicating) for row in rows]


async def _get_row(session: AsyncSession, crash_id: str) -> Optional[AnalysisModuleCrash]:
    result = await session.execute(
        select(AnalysisModuleCrash).where(AnalysisModuleCrash.uuid == crash_id)
    )
    return result.scalars().first()


async def get_crash_report(session: AsyncSession, crash_id: str) -> CrashReportDetail:
    """The full metadata for one crash report.

    Raises 400 for a malformed id, 404 when it does not exist, and 409 when it exists on another
    node and cannot be reached from here.
    """
    _validate_crash_id(crash_id)

    row = await _get_row(session, crash_id)
    local_node = _local_node()
    replicating = replication_enabled()

    # Resolution order depends on whether replication is on. With it off, node identity IS the
    # access decision and the node check comes first, exactly as before. With it on, node identity
    # stops meaning anything about reachability -- a report from any node may be in the bucket --
    # so we look for the bytes first and only fall back to the 409.
    if not replicating:
        if row is not None and row.node != local_node:
            _raise_wrong_node(crash_id, row.node)

    metadata = read_crash_report(crash_id, row.report_dir if row is not None else None)
    remote = False

    if metadata is None and replicating:
        # not on this node's disk: try the shared copy
        metadata = await run_in_threadpool(fetch_metadata, crash_id, get_temp_dir())
        if metadata is not None:
            remote = True
            metadata["complete"] = True
            metadata["report_dir"] = None
            sizes = await run_in_threadpool(remote_file_sizes, crash_id)
            metadata["files"] = [
                {"path": path, "size": size} for path, size in sorted(sizes.items())
            ]

    if metadata is None:
        if row is not None and row.node != local_node:
            # it exists, we know where, and it is not reachable from here
            _raise_wrong_node(crash_id, row.node)

        # indexed but the directory is gone: retention swept it, or it was never written
        raise HTTPException(status_code=404, detail="crash report not found")

    detail = CrashReportDetail(
        crash_id=crash_id,
        # "unknown" rather than a guess: an incomplete report with no index row genuinely does
        # not say what kind of crash it was, and inventing one would be a quiet lie
        crash_type=metadata.get("crash_type") or (row.crash_type if row is not None else "unknown"),
        node=metadata.get("node") or (row.node if row is not None else None),
        local=True,
        remote=remote,
        **{
            key: metadata[key]
            for key in (
                "complete", "report_dir", "timestamp", "hostname", "pid", "worker_name",
                "module_path", "module_name", "analysis_mode", "root_uuid",
                "root_storage_dir", "root_description", "observable_uuid", "observable_type",
                "observable_value", "maximum_analysis_time", "module_start_time",
                "elapsed_seconds", "file_name", "file_size", "file_sha256",
                "exception_type", "exception_message", "omitted", "files",
            )
            if key in metadata and metadata[key] is not None
        },
    )

    if row is not None:
        detail.insert_date = row.insert_date.isoformat() if row.insert_date else None
        detail.has_file = bool(row.has_file)
    else:
        detail.has_file = detail.file_name is not None

    return detail


def _raise_wrong_node(crash_id: str, node: str) -> None:
    """The report is on another node's disk and is not reachable from here.

    409 rather than 404, with the node named: "it is not here" and "it does not exist" are
    different answers, and only one of them tells the analyst what to do next. A redirect would
    be friendlier in a browser but would drop the credential -- both the x-ace-auth header and
    the session cookie are origin-scoped -- so it would land unauthenticated.

    This is now the *fallback*, not the default: with crash_reporting.replicate on, reports are
    copied to shared storage and any node can serve any of them. So the message names the setting
    -- the failure mode should explain its own fix rather than just telling an operator to go
    find another host.
    """
    hint = (
        "set crash_reporting.replicate to serve reports from any node"
        if not replication_enabled()
        else "the shared copy is missing; `ace crash sync` on that node will replicate it"
    )
    raise HTTPException(
        status_code=409,
        detail={
            "error": "wrong_node",
            "node": node,
            "message": (
                f"crash report {crash_id} is on node {node} and is not reachable from here; "
                f"request it from that node's API, or {hint}"
            ),
        },
    )


async def resolve_downloadable_report(session: AsyncSession, crash_id: str) -> Optional[str]:
    """Validate a download request and return the local report directory, or None to fetch it.

    Stays async and cheap on purpose: this runs on the event loop, so it does at most one
    existence check (in a threadpool) and never moves bytes. The actual download-and-stage happens
    inside create_encrypted_crash_zip(), which the router already runs in a threadpool.

    Returns the local directory when the report is on this node, or None when it must be pulled
    from shared storage.
    """
    _validate_crash_id(crash_id)

    row = await _get_row(session, crash_id)
    local_node = _local_node()
    replicating = replication_enabled()

    if not replicating:
        if row is not None and row.node != local_node:
            _raise_wrong_node(crash_id, row.node)

    crash_dir = find_crash_report_dir(crash_id, row.report_dir if row is not None else None)
    if crash_dir is not None:
        return crash_dir

    if replicating and await run_in_threadpool(remote_report_exists, crash_id):
        return None

    if row is not None and row.node != local_node:
        _raise_wrong_node(crash_id, row.node)

    raise HTTPException(status_code=404, detail="crash report not found")


def create_encrypted_crash_zip(crash_id: str, crash_dir: Optional[str]) -> str:
    """Build an encrypted zip of the whole crash report directory.

    Encrypted because a crash report contains, by construction, whatever the module choked on --
    see aceapi_v2/common/archive.py. Caller cleans up the returned zip.

    ``crash_dir`` of None means the report is not on this node and must be pulled from shared
    storage first. That staging happens here, inside the threadpool the router already puts this
    call in, and the staging directory is torn down before returning -- so the router's existing
    single BackgroundTask(unlink, zip_path) stays the whole cleanup story. Staging under
    get_temp_dir() also means etc/cron/daily/temp-files' -mtime +1 sweep is a backstop if the process
    dies mid-request.
    """
    if not is_valid_crash_id(crash_id):
        raise HTTPException(status_code=400, detail="invalid crash id")

    if crash_dir is not None:
        return _zip_report_dir(crash_id, crash_dir)

    with tempfile.TemporaryDirectory(prefix=f"crash-fetch-{crash_id}-", dir=get_temp_dir()) as staging:
        staged_dir = fetch_report(crash_id, staging)
        if staged_dir is None:
            raise HTTPException(status_code=404, detail="crash report not found")

        return _zip_report_dir(crash_id, staged_dir)


def _zip_report_dir(crash_id: str, crash_dir: str) -> str:
    """Zip one report directory, whose basename must be the crash id."""
    dest = os.path.join(get_temp_dir(), f"crash-{crash_id}.zip")
    remove_stale(dest)

    parent_dir = os.path.dirname(crash_dir)
    if os.path.basename(crash_dir) != crash_id:
        logger.error(
            "crash report dir basename %s does not match crash id %s",
            os.path.basename(crash_dir), crash_id,
        )
        raise HTTPException(status_code=500, detail="unexpected crash report layout")

    add_to_encrypted_zip(dest, parent_dir, crash_id, f"crash report {crash_id}")
    return dest
