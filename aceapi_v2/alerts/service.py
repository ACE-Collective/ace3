"""Alert service for ACE API v2."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid as uuidlib
from datetime import datetime

from fastapi import HTTPException

from saq.constants import ANALYSIS_MODE_CORRELATION, VALID_DIRECTIVES
from saq.database.model import Comment, ObservableComment, ObservableMapping
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload
from saq.environment import get_base_dir, get_temp_dir
from saq.gui.alert import GUIAlert
from saq.util import local_time
from saq.util.uuid import is_uuid

from aceapi_v2.alerts.schemas import BulkAddObservableResult
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)


ALERT_ZIP_PASSWORD = "infected"

# Name of the file added to the alert download zip (inside the "<uuid>/"
# directory) holding the analyst comments on the alert and on its observables.
# Comments live only in the database, not in the alert's storage directory.
ALERT_ZIP_COMMENTS_FILE = "comments.json"


def _resolve_alert(alert_uuid: str) -> GUIAlert:
    """Look up an alert by UUID and verify its storage directory is still on disk.

    Raises HTTPException with appropriate status for invalid UUID, missing alert,
    archived alert, or storage directory missing on disk.
    """
    if not is_uuid(alert_uuid):
        raise HTTPException(status_code=400, detail="invalid alert UUID")

    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")

    if alert.archived:
        raise HTTPException(
            status_code=410,
            detail="alert has been archived; storage has been cleaned up",
        )

    if not os.path.isdir(_alert_storage_path(alert)):
        raise HTTPException(
            status_code=410,
            detail="alert storage directory no longer exists on disk",
        )

    return alert


def _alert_storage_path(alert: GUIAlert) -> str:
    """Absolute path to the alert's storage directory."""
    return os.path.join(get_base_dir(), alert.storage_dir)


def _resolve_alert_storage_path(alert_uuid: str) -> str:
    """Look up an alert by UUID and return the absolute path to its storage directory."""
    return _alert_storage_path(_resolve_alert(alert_uuid))


def _serialize_user(user) -> dict:
    return {
        "username": user.username if user is not None else None,
        "display_name": user.display_name if user is not None else None,
    }


def collect_alert_comments(alert: GUIAlert) -> dict:
    """Return the analyst comments on the alert and on the observables mapped to it.

    Shape::

        {
            "alert_uuid": "...",
            "alert_comments": [
                {"insert_date": "...", "user": {...}, "comment": "..."}, ...
            ],
            "observable_comments": [
                {"observable": {"type": "...", "value": "...", "sha256": "..."},
                 "insert_date": "...", "user": {...}, "comment": "..."}, ...
            ],
        }
    """
    alert_comments = (
        get_db()
        .query(Comment)
        .filter(Comment.uuid == alert.uuid)
        .order_by(Comment.insert_date, Comment.comment_id)
        .all()
    )

    observable_comments = (
        get_db()
        .query(ObservableComment)
        .join(ObservableMapping, ObservableMapping.observable_id == ObservableComment.observable_id)
        .filter(ObservableMapping.alert_id == alert.id)
        .order_by(ObservableComment.insert_date, ObservableComment.id)
        .all()
    )

    return {
        "alert_uuid": alert.uuid,
        "alert_comments": [
            {
                "insert_date": c.insert_date.isoformat(),
                "user": _serialize_user(c.user),
                "comment": c.comment,
            }
            for c in alert_comments
        ],
        "observable_comments": [
            {
                "observable": {
                    "type": c.observable.type,
                    "value": c.observable.display_value,
                    "sha256": c.observable.sha256.hex(),
                },
                "insert_date": c.insert_date.isoformat(),
                "user": _serialize_user(c.user),
                "comment": c.comment,
            }
            for c in observable_comments
        ],
    }


def _run_zip(dest: str, cwd: str, target: str, alert_uuid: str) -> None:
    """Add ``target`` (relative to ``cwd``) to the encrypted zip at ``dest``.

    Running against an existing archive appends to it, so the storage directory
    and the generated comments file can be added from different working
    directories while both land under the "<uuid>/" prefix.
    """
    proc = subprocess.run(
        ["zip", "-e", "-P", ALERT_ZIP_PASSWORD, "-r", dest, "--", target],
        cwd=cwd,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        logger.error(
            "zip failed for alert %s (rc=%s): %s",
            alert_uuid,
            proc.returncode,
            proc.stderr.decode(errors="replace"),
        )
        try:
            os.remove(dest)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail="failed to create alert zip")


def create_encrypted_alert_zip(alert_uuid: str) -> str:
    """Build an encrypted (password='infected') zip of the alert's storage
    directory under the configured temp dir. Returns the absolute path to
    the resulting zip file. Caller is responsible for cleaning it up.

    The zip also carries ``<uuid>/comments.json`` (see ``collect_alert_comments``)
    so the analyst comments, which exist only in the database, travel with the
    alert. The storage directory itself is never written to.
    """
    alert = _resolve_alert(alert_uuid)
    storage_dir = _alert_storage_path(alert)
    comments = collect_alert_comments(alert)

    dest = os.path.join(get_temp_dir(), f"{alert_uuid}.zip")
    # If a stale file is hanging around, remove it so zip doesn't try to update it.
    if os.path.exists(dest):
        try:
            os.remove(dest)
        except OSError:
            pass

    parent_dir = os.path.dirname(storage_dir)
    if os.path.basename(storage_dir) != alert_uuid:
        logger.error(
            "storage dir basename %s does not match alert uuid %s",
            os.path.basename(storage_dir),
            alert_uuid,
        )
        raise HTTPException(status_code=500, detail="unexpected alert storage layout")

    _run_zip(dest, parent_dir, alert_uuid, alert_uuid)

    # Stage the comments file under a "<uuid>/" directory of its own so it
    # lands next to data.json in the archive without touching the storage dir.
    staging_dir = tempfile.mkdtemp(prefix="alert-comments-", dir=get_temp_dir())
    try:
        os.mkdir(os.path.join(staging_dir, alert_uuid))
        with open(os.path.join(staging_dir, alert_uuid, ALERT_ZIP_COMMENTS_FILE), "w") as fp:
            json.dump(comments, fp, indent=2)

        _run_zip(dest, staging_dir, os.path.join(alert_uuid, ALERT_ZIP_COMMENTS_FILE), alert_uuid)
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)

    return dest


def resolve_alert_log_path(alert_uuid: str) -> str:
    """Return the absolute path to the alert's saq.log file."""
    storage_dir = _resolve_alert_storage_path(alert_uuid)
    log_path = os.path.join(storage_dir, "saq.log")
    if not os.path.isfile(log_path):
        raise HTTPException(
            status_code=404, detail="saq.log not present for this alert"
        )
    return log_path


def _add_observable_to_alert(
    alert_uuid: str,
    o_type: str,
    o_value: str,
    o_time: datetime | None,
    directives: list[str],
    username: str,
) -> str | None:
    """Add an observable to a single alert. Returns None on success, or a failure reason string.

    This is a synchronous function that performs filesystem lock/load/sync
    operations. It uses the sync get_db() because Alert.sync()
    (saq/database/model.py) calls Session.object_session(self) to get a sync
    session for its session.add(self) + session.commit() — meaning the Alert
    ORM object must be loaded from a sync session to begin with.

    TODO: refactor Alert.sync() to separate filesystem save from the sync DB
    commit so this service can use AsyncSession end-to-end.
    """
    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one_or_none()
    if alert is None:
        logger.error("alert %s not found in database", alert_uuid)
        return "alert not found"

    lock_uuid = str(uuidlib.uuid4())
    try:
        if not acquire_lock(uuid=str(alert.uuid), lock_uuid=lock_uuid):
            logger.warning("unable to acquire lock on alert %s", alert_uuid)
            return "alert is currently locked"

        alert.lock_uuid = lock_uuid
        alert.load()

        # remember whether this observable already existed (e.g. added by the engine)
        # so we don't mislabel it as analyst-added
        already_existed = alert.root_analysis.get_observable_by_spec(o_type, o_value, o_time) is not None

        observable = alert.root_analysis.add_observable_by_spec(o_type, o_value, o_time)

        # track who manually added this observable and when
        if observable and not already_existed:
            observable.added_by = username
            observable.added_time = local_time()

        if observable and directives:
            for directive in directives:
                if directive in VALID_DIRECTIVES:
                    observable.add_directive(directive)

        alert.root_analysis.analysis_mode = ANALYSIS_MODE_CORRELATION
        alert.sync()
        add_workload(alert.root_analysis)
        return None

    except Exception as e:
        logger.error("unable to add observable to alert %s: %s", alert_uuid, e)
        return f"unexpected error: {e}"

    finally:
        try:
            if alert.lock_uuid:
                release_lock(str(alert.uuid), alert.lock_uuid)
        except Exception:
            logger.error("unable to release lock on alert %s", alert_uuid)


async def bulk_add_observable(
    alert_uuids: list[str],
    o_type: str,
    o_value: str,
    o_time: datetime | None,
    directives: list[str],
    username: str,
) -> BulkAddObservableResult:
    """Add an observable to multiple alerts.

    Runs sync filesystem operations in a thread pool via run_db_in_thread(),
    which resets the worker thread's sync session after each call.
    """
    logger.info(
        f"AUDIT: user {username} bulk-added observable "
        f"({o_type},{o_value},{o_time}) to alerts {alert_uuids}"
    )

    # Validate directives
    valid_directives = [d for d in directives if d in VALID_DIRECTIVES]

    success_count = 0
    failed_uuids = []
    failed_details = {}

    for alert_uuid in alert_uuids:
        failure_reason = await run_db_in_thread(
            _add_observable_to_alert, alert_uuid, o_type, o_value, o_time, valid_directives, username
        )
        if failure_reason is None:
            success_count += 1
        else:
            failed_uuids.append(alert_uuid)
            failed_details[alert_uuid] = failure_reason

    return BulkAddObservableResult(
        success_count=success_count,
        failed_count=len(failed_uuids),
        failed_uuids=failed_uuids,
        failed_details=failed_details,
    )
