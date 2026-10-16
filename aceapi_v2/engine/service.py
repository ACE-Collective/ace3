"""Engine service (ACE API v2).

Sync helpers over a work target's storage directory and the engine's database rows, run through
run_db_in_thread. Every caller is another ACE node, with the automation key (engine:*).
"""

import logging
import os
import shutil
import tarfile
import uuid as uuidlib
from typing import IO

from fastapi import HTTPException

from aceapi_v2.engine.schemas import UploadModifiers
from saq.analysis import RootAnalysis
from saq.configuration.config import get_engine_config
from saq.constants import ANALYSIS_MODE_CORRELATION
from saq.database.model import Alert
from saq.database.pool import get_db, get_db_connection
from saq.database.util.alert import ALERT
from saq.environment import get_global_runtime_settings, get_temp_dir
from saq.util import storage_dir_from_uuid, workload_storage_dir
from saq.util.uuid import UUID_REGEX

logger = logging.getLogger(__name__)


def _validate_uuid(value: str, what: str = "uuid") -> None:
    if not UUID_REGEX.fullmatch(value):
        raise HTTPException(status_code=400, detail=f"invalid {what} {value!r}")


def _existing_target_dir(uuid: str) -> str:
    """The storage directory of a work target on this node: its storage directory, or its
    directory in the engine's work_dir when one is configured. 404 when neither exists."""
    _validate_uuid(uuid)
    target_dir = storage_dir_from_uuid(uuid)
    if get_engine_config().work_dir and not os.path.isdir(target_dir):
        target_dir = workload_storage_dir(uuid)

    if not os.path.isdir(target_dir):
        raise HTTPException(status_code=404, detail=f"unknown work target {uuid}")

    return target_dir


def create_download_tar(uuid: str) -> str:
    """A tar of the work target's storage directory in the temp dir; the caller removes it."""
    target_dir = _existing_target_dir(uuid)
    path = os.path.join(get_temp_dir(), f"download_{uuid}_{uuidlib.uuid4()}.tar")
    try:
        with tarfile.open(path, mode="w") as tar:
            tar.add(target_dir, ".")
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        raise

    return path


def _alert_exists(uuid: str) -> bool:
    return get_db().query(Alert.id).filter(Alert.uuid == uuid).first() is not None


def receive_upload(uuid: str, archive: IO[bytes], modifiers: UploadModifiers) -> str:
    """Extract an uploaded work target into its storage directory on this node, and take it over:
    its location and company become this node's, a moved alert's row is repointed here, a
    correlation root gets its alert row, and sync schedules it. Returns the storage directory."""
    _validate_uuid(uuid)
    target_dir = storage_dir_from_uuid(uuid)

    created = False
    if os.path.exists(target_dir):
        if not modifiers.overwrite:
            raise HTTPException(
                status_code=409,
                detail=f"{target_dir} already exists (specify the overwrite modifier to replace the data)")
    else:
        os.makedirs(target_dir)
        created = True

    # the archive is extracted as it is read; the data filter refuses absolute paths, links out of
    # the directory and special files
    try:
        with tarfile.open(fileobj=archive, mode="r|") as tar:
            tar.extractall(path=target_dir, filter="data")
    except tarfile.TarError as e:
        if created:
            shutil.rmtree(target_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"invalid archive: {e}")

    logger.info("extracted %s to %s", uuid, target_dir)

    root = RootAnalysis(storage_dir=target_dir)
    root.load()
    root.location = get_global_runtime_settings().saq_node
    root.company_id = get_global_runtime_settings().company_id
    root.company_name = get_global_runtime_settings().company_name
    root.save()

    if modifiers.is_alert and modifiers.move:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("UPDATE alerts SET location = %s, storage_dir = %s WHERE uuid = %s",
                           (root.location, root.storage_dir, uuid))
            db.commit()

    # A correlation-mode root is an alert. submit_local() inserts its alerts row before scheduling
    # it; a root uploaded from another node (RemoteNode.submit_remote, the remote branch of
    # `ace correlate`) has to get its row here, on the node that now owns it -- the engine only
    # syncs an existing row, so without this the alert is analyzed and lost. A move or a drain
    # carries an alert that already has its row.
    if root.analysis_mode == ANALYSIS_MODE_CORRELATION and not _alert_exists(uuid):
        ALERT(root)
        logger.info("created the alert row for an uploaded correlation root", extra={"alert_uuid": uuid})

    if modifiers.sync:
        root.schedule()

    return root.storage_dir


def clear_target(uuid: str, lock_uuid: str) -> None:
    """Delete a work target's storage directory on this node, after the node that took the work
    target over has copied it. The caller must hold the target's lock, named by lock_uuid."""
    _validate_uuid(uuid)
    _validate_uuid(lock_uuid, "lock uuid")

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uuid FROM locks WHERE uuid = %s AND lock_uuid = %s", (uuid, lock_uuid))
        if cursor.fetchone() is None:
            logger.warning("request to clear %s with a lock uuid %s that does not hold it", uuid, lock_uuid)
            raise HTTPException(status_code=409, detail=f"lock {lock_uuid} does not hold {uuid}")

    target_dir = _existing_target_dir(uuid)
    logger.info("clearing target directory %s", target_dir)
    shutil.rmtree(target_dir)
