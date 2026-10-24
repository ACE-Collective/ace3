"""Analysis submission service (ACE API v2).

Builds a RootAnalysis from a submission (`ace_api.submit()`, `ace submit`, `ace hunt`, the GUI's
New Alert, other tools) and queues it on this node. Sync: the root is written to disk and the
alert row through the synchronous get_db() session, so it runs through run_db_in_thread.
"""

import logging
import shutil
import uuid as uuidlib
from datetime import datetime
from typing import IO

from fastapi import HTTPException

from saq.analysis import RootAnalysis
from saq.configuration import get_config
from saq.configuration.config import get_engine_config
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    EVENT_TIME_FORMAT_JSON_TZ,
    F_FILE,
    NODE_STATUS_DRAINED,
    NODE_STATUS_DRAINING,
    QUEUE_DEFAULT,
)
from saq.database import ALERT
from saq.database.util.node import get_node_status
from saq.environment import get_global_runtime_settings, get_local_timezone
from saq.observables.generator import create_observable_from_dict
from saq.util import parse_event_time, storage_dir_from_uuid
from saq.util.hashing import sha256_file

logger = logging.getLogger(__name__)

# the name an upload is stored under when the client sent it without one
DEFAULT_UPLOAD_NAME = "upload"


def reject_if_node_draining() -> None:
    """503 when this node is draining or drained: a submission is always queued on the node that
    receives it, so a draining node refuses work for its drain to finish."""
    node_id = get_global_runtime_settings().saq_node_id
    if node_id is None:
        return

    if get_node_status(node_id) in (NODE_STATUS_DRAINING, NODE_STATUS_DRAINED):
        raise HTTPException(
            status_code=503,
            detail=f"node {get_global_runtime_settings().saq_node} is draining; submit to another node")


def _add_file(root: RootAnalysis, file_name: str | None, fp: IO[bytes], file_observable_dicts: list[dict]) -> str | None:
    """Store an uploaded file in the root as a file observable, with what the submission said
    about it (matched on its sha256). Returns its path, or None when it was not added."""
    # the client chooses the name, and may place the file in a subdirectory (ace_api's
    # relative_storage_path); the file manager cleans it so it stays inside the root's files
    # directory, and gives a name two uploads share (every unnamed one) a suffix
    full_path = root.create_output_file(file_name or DEFAULT_UPLOAD_NAME)

    with open(full_path, "wb") as out:
        shutil.copyfileobj(fp, out)

    file_sha256 = sha256_file(full_path)
    observable_dict = next((d for d in file_observable_dicts if d["value"] == file_sha256), {"value": file_sha256})

    # stored where it was written: the observable's file_path is the client's name for the same
    # upload, and is no more trustworthy than the upload's own
    file_observable = root.add_file_observable(full_path)
    if not file_observable:
        return None

    for tag in observable_dict.get("tags", []):
        file_observable.add_tag(tag)
    for directive in observable_dict.get("directives", []):
        file_observable.add_directive(directive)
    for limited_analysis in observable_dict.get("limited_analysis", []):
        file_observable.limit_analysis(limited_analysis)
    if observable_dict.get("added_by"):
        file_observable.added_by = observable_dict["added_by"]
    if observable_dict.get("added_time"):
        file_observable.added_time = observable_dict["added_time"]

    return file_observable.full_path


def submit(submission: dict, files: list[tuple[str, IO[bytes]]], remote_addr: str) -> str:
    """Create a root from a submission and queue it on this node; a correlation-mode root is
    inserted as an alert first. Returns its uuid. A submission that fails part-way leaves nothing
    behind."""
    reject_if_node_draining()

    company_name = submission.get("company_name")
    if company_name is not None and company_name != get_config().global_settings.company_name:
        raise HTTPException(
            status_code=400, detail=f"wrong company {company_name} (are you sending to the correct system?)")

    if "description" not in submission:
        raise HTTPException(status_code=400, detail="missing description field in submission")

    # no event time (or a null one) is now
    event_time = get_local_timezone().localize(datetime.now())
    if submission.get("event_time") is not None:
        try:
            event_time = parse_event_time(submission["event_time"])
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"invalid event time format for {submission['event_time']} (use {EVENT_TIME_FORMAT_JSON_TZ} format)")

    root_uuid = str(uuidlib.uuid4())
    root = RootAnalysis(uuid=root_uuid, storage_dir=storage_dir_from_uuid(root_uuid))
    root.initialize_storage()
    try:
        root.analysis_mode = submission.get("analysis_mode") or get_engine_config().default_analysis_mode
        root.company_id = submission.get("company_id") or get_config().global_settings.company_id
        root.tool = submission.get("tool", "api")
        root.tool_instance = submission.get("tool_instance", f"api({remote_addr})")
        root.alert_type = submission.get("type", get_config().api.default_alert_type)
        root.description = submission["description"]
        root.event_time = event_time
        root.queue = submission.get("queue", QUEUE_DEFAULT)
        root.instructions = submission.get("instructions")
        root.extensions = submission.get("extensions")
        root.details = submission.get("details", {})

        for tag in submission.get("tags", []):
            root.add_tag(tag)

        # file observables are described here but added with their files below
        file_observable_dicts = []
        for observable_dict in submission.get("observables", []):
            if observable_dict.get("type") == F_FILE:
                file_observable_dicts.append(observable_dict)
            else:
                try:
                    observable = create_observable_from_dict(observable_dict)
                except (KeyError, TypeError, ValueError) as e:
                    raise HTTPException(status_code=400, detail=f"invalid observable {observable_dict!r}: {e!r}")
                root.add_observable(observable)

        file_list = []
        for file_name, fp in files:
            logger.info("recording file %s", file_name)
            path = _add_file(root, file_name, fp, file_observable_dicts)
            if path:
                file_list.append(path)

        if not root.save():
            raise HTTPException(status_code=500, detail="unable to save the submission")

        if root.analysis_mode == ANALYSIS_MODE_CORRELATION:
            ALERT(root)

        root.schedule()

    except BaseException:
        shutil.rmtree(root.storage_dir, ignore_errors=True)
        raise

    try:
        root.record_submission(submission, file_list)
    except Exception as e:
        logger.error("unable to record submission data for %s: %s", root.uuid, e)

    return root.uuid
