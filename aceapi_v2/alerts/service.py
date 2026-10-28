"""Alert service for ACE API v2."""

import json
import logging
import os
import shutil
import tempfile
import uuid as uuidlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import aliased

from saq.analysis.observable import Observable
from saq.analysis.root import load_file_observable
from saq.clicker_detection.config import build_splunk_clicker_search_urls, load_clicker_config
from saq.clicker_detection.timeline import REGISTERED_CLICKER_PROVIDERS
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    DIRECTIVE_CLICKER_DETECTION,
    DIRECTIVE_COLLECT_FILE,
    DIRECTIVE_CRAWL,
    DIRECTIVE_RENDER,
    F_FILE,
    F_FILE_LOCATION,
    F_FQDN,
    F_URL,
    VALID_DIRECTIVES,
)
from saq.database.model import (
    Alert,
    Comment,
    Company,
    DetectionPoint,
    ObservableComment,
    ObservableMapping,
    Tag,
    TagMapping,
    User,
)
from saq.database.pool import get_db
from saq.database.util.alert import (
    AlertFrozen,
    change_alert_owner,
    describe_skipped,
    ensure_not_frozen,
    node_scope_locations,
    touch_alerts,
)
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload, request_analyst_analysis
from saq.environment import get_base_dir, get_temp_dir
from saq.gui.alert import GUIAlert
from saq.gui.filter_query import resolve_filter_list, uses_filter_sentinels
from saq.gui.filter_screens import ALERTS_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.json_encoding import _JSONEncoder
from saq.logging import log_audit
from saq.observables.file import FileObservable
from saq.search.query import build_listing_query
from saq.search.tasks import submit_index_task
from saq.search.types import SearchFilters
from saq.svs.alert_status import alert_svs_statuses
from saq.util import local_time
from saq.util.ui import hexdump_lines
from saq.util.uuid import is_uuid

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.alerts.schemas import (
    ALERT_ROW_CSV_FIELDS,
    AlertCommentRead,
    AlertListRow,
    AlertRow,
    BulkAddObservableResult,
    ClickerSearch,
    SetOwnerResult,
)
from aceapi_v2.common.archive import ZIP_PASSWORD, add_to_encrypted_zip, safe_file_name
from aceapi_v2.common.listing import (
    CHANGED_SINCE_SETTLE_SECONDS,
    InvalidCursor,
    InvalidListingRequest,
    decode_cursor,
    encode_cursor,
    rows_to_csv,
    settled,
)
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)


# re-exported from the shared helper: this name predates it and is referenced by tests and by
# the Flask export view
ALERT_ZIP_PASSWORD = ZIP_PASSWORD

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


def etag(version: str) -> str:
    """The alert version token as an HTTP entity tag (shared by the v2 and AI apps)."""
    return f'"{version}"'


def etag_matches(if_none_match: str, version: str) -> bool:
    """True if the If-None-Match header names the given version (or is the wildcard)."""
    for candidate in if_none_match.split(","):
        candidate = candidate.strip()
        if candidate == "*":
            return True
        candidate = candidate.removeprefix("W/")
        if candidate.strip('"') == version:
            return True
    return False


def get_alert_version(alert_uuid: str) -> str:
    """Return the alert's current version token without loading the alert.

    This is the cheap path a polling client hits: one indexed read on alerts.uuid.
    """
    if not is_uuid(alert_uuid):
        raise HTTPException(status_code=400, detail="invalid alert UUID")

    version = get_db().query(Alert.version).filter(Alert.uuid == alert_uuid).scalar()
    if version is None:
        raise HTTPException(status_code=404, detail="alert not found")

    return version


def set_alert_owner(alert_uuids: list[str], owner_id: int | None, acting_user_id: int,
                    take_owned: dict[str, int]) -> SetOwnerResult:
    """Gives the alerts to owner_id (see change_alert_owner) and reports what was left alone,
    worded as the GUI tells the analyst."""
    new_owner = None
    if owner_id is not None:
        new_owner = get_db().get(User, owner_id)
        if new_owner is None or not new_owner.enabled:
            raise HTTPException(status_code=422, detail=f"user {owner_id} does not exist or is disabled")

    ownership = change_alert_owner(alert_uuids, owner_id, acting_user_id, take_owned)

    skipped = describe_skipped(ownership)
    message = None
    if skipped:
        count = len(ownership.permitted)
        if owner_id == acting_user_id:
            action = f"took ownership of {count} alerts"
        elif owner_id is None:
            action = f"unassigned {count} alerts"
        else:
            action = f"assigned {count} alerts to {new_owner.gui_display}"
        message = f"{action}; {skipped}"

    return SetOwnerResult(applied=ownership.permitted, skipped=ownership.skipped, message=message)


def get_alert_meta(alert_uuid: str) -> dict:
    """The ownership, disposition, lock and version state the alert page polls for.

    Database state only: the alert is not loaded from disk, and an archived alert still has it.
    """
    if not is_uuid(alert_uuid):
        raise HTTPException(status_code=400, detail="invalid alert UUID")

    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")

    return alert.get_metadata_json()


def get_alert_json(alert_uuid: str) -> dict:
    """Load the alert from disk and return its full JSON (analysis tree plus database state,
    including the version token under Alert.KEY_VERSION)."""
    alert = _resolve_alert(alert_uuid)
    alert.load()
    return alert.json


def get_alert(alert_uuid: str) -> tuple[str, str]:
    """Return (body, version) for GET /alerts/{uuid}.

    The body is ``{"result": <alert JSON>}`` encoded with the legacy encoder, which knows
    how to render the datetimes, bytes and other objects found in an analysis tree.
    """
    alert_json = get_alert_json(alert_uuid)
    body = json.dumps({"result": alert_json}, cls=_JSONEncoder, sort_keys=True)
    return body, alert_json[Alert.KEY_VERSION]


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


def update_alert_comment(alert_uuid: str, comment_id: int, comment_text: str, auth: ApiAuthResult) -> AlertCommentRead:
    """Replace the text of an analyst comment on an alert. Only the comment's author may edit it.

    The alert's version is rotated and the alert re-indexed, as when a comment is added."""
    user_id = auth.auth_user_id
    if user_id is None:
        raise HTTPException(status_code=401, detail="User authentication required")

    if not is_uuid(alert_uuid):
        raise HTTPException(status_code=400, detail="invalid alert UUID")

    comment = (
        get_db()
        .query(Comment)
        .filter(Comment.comment_id == comment_id, Comment.uuid == alert_uuid)
        .one_or_none()
    )
    if comment is None:
        raise HTTPException(status_code=404, detail="comment not found")

    if comment.user_id != user_id:
        raise HTTPException(status_code=403, detail="Only the comment author can edit this comment")

    # a comment added through the GUI's form was stored with a form submission's CRLF line breaks,
    # while the edit modal sends a textarea's LF ones, so saving it untouched is not a change
    if comment.comment.replace("\r\n", "\n") != comment_text.replace("\r\n", "\n"):
        log_audit("user %s edited comment %s on alert %s from %r to %r",
                  auth.auth_name, comment_id, alert_uuid, comment.comment, comment_text,
                  auth=auth, alert_uuid=alert_uuid, comment_id=comment_id)
        comment.comment = comment_text
        touch_alerts([alert_uuid])
        get_db().commit()
        submit_index_task(alert_uuid)

    return AlertCommentRead(
        comment_id=comment.comment_id,
        alert_uuid=comment.uuid,
        insert_date=comment.insert_date,
        user_id=comment.user_id,
        user_display_name=comment.user.display_name if comment.user else "unknown",
        comment=comment.comment,
    )


def _run_zip(dest: str, cwd: str, target: str, alert_uuid: str) -> None:
    """Add ``target`` (relative to ``cwd``) to the encrypted zip at ``dest``.

    Running against an existing archive appends to it, so the storage directory
    and the generated comments file can be added from different working
    directories while both land under the "<uuid>/" prefix.

    Thin wrapper kept so this module's call sites and tests read unchanged; the
    implementation is shared with the crash report download.
    """
    add_to_encrypted_zip(dest, cwd, target, f"alert {alert_uuid}")


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


def resolve_alert_file(alert_uuid: str, observable_uuid: str) -> FileObservable:
    """A file observable of the alert whose file is on disk; 404 otherwise.

    Only that one observable is loaded, never the analysis tree (see load_file_observable).
    """
    file_observable = load_file_observable(_resolve_alert_storage_path(alert_uuid), observable_uuid)
    if file_observable is None or not os.path.exists(file_observable.path):
        raise HTTPException(status_code=404, detail="unknown file")

    return file_observable


def resolve_alert_image(alert_uuid: str, observable_uuid: str) -> tuple[str, str]:
    """Return (path, mime type) of a file observable of the alert that is an image.

    The alert page fetches one of these per image it shows. The URL can also be opened as a
    page, so a file that is not an image is a 404 rather than something the browser would render
    on the GUI origin.
    """
    file_observable = resolve_alert_file(alert_uuid, observable_uuid)
    if not file_observable.is_image:
        raise HTTPException(status_code=404, detail="not an image")

    return file_observable.path, file_observable.mime_type


# how many lines of a hex dump are sent at once
_HEXDUMP_BATCH_LINES = 4096


def hexdump(path: str) -> Iterator[str]:
    """The file as `hexdump -C` prints it, in batches of lines."""
    lines: list[str] = []
    with open(path, "rb") as fp:
        for line in hexdump_lines(iter(lambda: fp.read(16), b"")):
            lines.append(line)
            if len(lines) >= _HEXDUMP_BATCH_LINES:
                yield "".join(lines)
                lines = []

    if lines:
        yield "".join(lines)


def create_encrypted_file_zip(alert_uuid: str, observable_uuid: str) -> tuple[str, str]:
    """Zip a file observable of the alert, encrypted with the password infected (see
    aceapi_v2/common/archive.py). Returns (zip path, name to download it as); the caller removes
    the zip."""
    file_observable = resolve_alert_file(alert_uuid, observable_uuid)
    path = file_observable.path
    dest = os.path.join(get_temp_dir(), f"{uuidlib.uuid4()}.zip")
    add_to_encrypted_zip(dest, os.path.dirname(path), os.path.basename(path), f"alert {alert_uuid} file {observable_uuid}")
    return dest, f"{safe_file_name(os.path.basename(path))}.zip"


#
# analysis an analyst requests for one observable (the alert page's observable actions)
#

# the analysis module whose configuration holds the Splunk clicker searches
CLICKER_SPLUNK_MODULE_NAME = "clicker_detection_splunk"


def request_observable_analysis(alert_uuid: str, observable_uuid: str, valid_types: tuple[str, ...],
                                change: Callable[[Observable], None]) -> str:
    """Change one observable of the alert (add the directive an analysis module waits for), and
    queue the alert for the analysis the analyst asked for. Returns the observable as text, for
    the audit log. The observable actions of integrations use it too.

    request_analyst_analysis() puts the alert back in correlation mode and past the stop on a
    dispositioned alert, so the requested analysis runs on an alert the analyst already worked.
    404 for an unknown alert or observable, 422 for an observable of another type, and 409 while
    the engine, or anything else, holds the alert's lock, or for a SIMULATED alert, which is never
    re-analyzed (ensure_not_frozen)."""
    alert = _resolve_alert(alert_uuid)
    try:
        ensure_not_frozen(alert)
    except AlertFrozen as e:
        raise HTTPException(status_code=409, detail=str(e))

    lock_uuid = str(uuidlib.uuid4())
    if not acquire_lock(str(alert.uuid), lock_uuid):
        raise HTTPException(status_code=409, detail="the alert is being analyzed; try again in a moment")

    try:
        if not alert.load():
            raise HTTPException(status_code=500, detail="unable to load the alert")

        observable = alert.root_analysis.get_observable(observable_uuid)
        if observable is None:
            raise HTTPException(status_code=404, detail="observable not found")

        if observable.type not in valid_types:
            raise HTTPException(status_code=422, detail=f"this applies to {' and '.join(valid_types)} observables, not {observable.type}")

        change(observable)
        request_analyst_analysis(alert.root_analysis)
        alert.sync()
        add_workload(alert.root_analysis)
        return str(observable)
    finally:
        release_lock(str(alert.uuid), lock_uuid)


def request_file_collection(alert_uuid: str, observable_uuid: str) -> str:
    """Collect File: the file collectors fetch the file at this location from its host."""
    return request_observable_analysis(
        alert_uuid, observable_uuid, (F_FILE_LOCATION,),
        lambda observable: observable.add_directive(DIRECTIVE_COLLECT_FILE))


def request_render(alert_uuid: str, observable_uuid: str) -> str:
    """Render: phishkit renders the file (HTML and PDF) and takes a screenshot."""
    return request_observable_analysis(
        alert_uuid, observable_uuid, (F_FILE,),
        lambda observable: observable.add_directive(DIRECTIVE_RENDER))


def request_crawl(alert_uuid: str, observable_uuid: str) -> str:
    """Crawl: phishkit downloads the URL's content and takes a screenshot."""
    return request_observable_analysis(
        alert_uuid, observable_uuid, (F_URL,),
        lambda observable: observable.add_directive(DIRECTIVE_CRAWL))


def _check_for_clickers(observable: Observable) -> None:
    observable.add_directive(DIRECTIVE_CLICKER_DETECTION)
    # An analyst asking again wants a fresh check. The engine skips a module whose analysis
    # already exists (saq/modules/base_module.py accepts()), so the earlier clicker analyses are
    # dropped. delete_analysis also prunes what the old analysis owned (its detection points,
    # observables and detail files); the sync that follows reconciles the detection_points table.
    for existing in list(observable.all_analysis):
        if type(existing) in REGISTERED_CLICKER_PROVIDERS:
            observable.delete_analysis(existing)


def request_clicker_check(alert_uuid: str, observable_uuid: str) -> str:
    """Check for clickers: every configured clicker module looks for anyone who clicked the URL or
    visited the domain."""
    return request_observable_analysis(alert_uuid, observable_uuid, (F_URL, F_FQDN), _check_for_clickers)


def load_observable(alert_uuid: str, observable_uuid: str) -> Observable:
    """One observable of the alert, for an action that reads it and changes nothing, so the alert
    is not locked. 404 for an unknown alert or observable."""
    alert = _resolve_alert(alert_uuid)
    if not alert.load():
        raise HTTPException(status_code=500, detail="unable to load the alert")

    observable = alert.root_analysis.get_observable(observable_uuid)
    if observable is None:
        raise HTTPException(status_code=404, detail="observable not found")

    return observable


def clicker_searches(alert_uuid: str, observable_uuid: str) -> list[ClickerSearch]:
    """The Splunk searches the clicker check would run for the observable, as Splunk web URLs, so
    an analyst can run them without the check. Empty when none is configured for its type."""
    observable = load_observable(alert_uuid, observable_uuid)

    # no block means the Splunk clicker module is not configured on this node; a block that fails
    # validation raises instead, since an empty list would read as "no searches for this observable"
    if not get_config().has_analysis_module_config(CLICKER_SPLUNK_MODULE_NAME):
        return []

    module_config = get_analysis_module_config(CLICKER_SPLUNK_MODULE_NAME)

    config = load_clicker_config(module_config.config_path)
    return [ClickerSearch(name=search["name"], url=search["url"])
            for search in build_splunk_clicker_search_urls(config, observable, api_name=module_config.api_name)]


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

    try:
        ensure_not_frozen(alert)
    except AlertFrozen as e:
        return str(e)

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
        if observable is None:
            # the value is impossible for this type, so nothing was added. Return a failure so
            # it is not counted as a success, and skip the sync so a rejected spec does not
            # schedule a correlation pass.
            return f"{o_value!r} is not a valid value for observable type {o_type}"

        # track who manually added this observable and when
        if not already_existed:
            observable.added_by = username
            observable.added_time = local_time()

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
    auth: ApiAuthResult,
) -> BulkAddObservableResult:
    """Add an observable to multiple alerts.

    Runs sync filesystem operations in a thread pool via run_db_in_thread(),
    which resets the worker thread's sync session after each call.
    """
    username = auth.auth_name or "unknown"
    log_audit("user %s bulk-added observable (%s,%s,%s) to alerts %s", username, o_type, o_value, o_time,
              alert_uuids, auth=auth, alert_uuids=alert_uuids, observable_type=o_type, observable_value=o_value)

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


#
# GET /api/v2/alerts: the alert listing for export and reporting
#
# One SQL path with the search listing (saq.search.query.build_listing_query), paged by keyset
# instead of offset: a report builder pulling every alert must not skip or repeat rows while
# new alerts arrive. The statement is built ONCE per request (relative dates resolve then, and
# building the filters runs queries of its own) and each page is executed in its own thread
# through run_db_in_thread, returning plain data only.
#

LISTING_ORDER_ID = "id"
LISTING_ORDER_UPDATED = "updated_at"


@dataclass(frozen=True)
class AlertListing:
    """A prepared listing: the filtered, scoped statement selecting (Alert.id,
    Alert.updated_at), with no order or limit, and the order its pages follow."""

    statement: Select
    order: str


def _to_utc_naive(value: datetime) -> datetime:
    # TIMESTAMP columns are compared in the session time zone, which ACE runs as UTC
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def prepare_alert_listing(
    filter_params: list[str], *, changed_since: datetime | None, tz, viewer_user_id: int | None
) -> AlertListing:
    """Builds the listing statement from share-link filters (`f=`), resolved the way the manage
    page resolves them ($USER / $USER_QUEUE against the caller, repeats of one filter ORed) and
    scoped to this node's alerts exactly as the GUI is. Raises InvalidListingRequest."""
    try:
        entries, _ = decode_filter_query(filter_params, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        entries = [entry.model_dump() for entry in ALERTS_SCREEN.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))

    user_queue = user_display_name = None
    if uses_filter_sentinels(entries):
        viewer = get_db().get(User, viewer_user_id) if viewer_user_id is not None else None
        if viewer is None:
            raise InvalidListingRequest("$USER and $USER_QUEUE need a caller that is a user")
        user_queue, user_display_name = viewer.queue, viewer.display_name

    entries = resolve_filter_list(entries, user_queue=user_queue, user_display_name=user_display_name)

    locations = node_scope_locations()
    filters = SearchFilters(
        filter_list=tuple(entries),
        locations=tuple(locations) if locations is not None else None,
        timezone=tz,
    )

    query = build_listing_query(filters)
    order = LISTING_ORDER_ID
    if changed_since is not None:
        order = LISTING_ORDER_UPDATED
        query = query.filter(Alert.updated_at >= _to_utc_naive(changed_since))

    # no filter fans the rows out (see filter_listing); DISTINCT is insurance, and valid
    # under ONLY_FULL_GROUP_BY because every column the pages order by is selected
    statement = query.with_entities(Alert.id, Alert.updated_at).distinct().statement
    return AlertListing(statement=statement, order=order)


def encode_listing_cursor(order: str, alert_id: int, updated_at: datetime) -> str:
    key = [alert_id] if order == LISTING_ORDER_ID else [updated_at.isoformat(), alert_id]
    return encode_cursor(o=order, k=key)


def decode_listing_cursor(cursor: str, order: str) -> list:
    """The keyset values a cursor carries. Raises InvalidCursor."""
    def parse(payload: dict) -> list:
        if payload["o"] != order:
            raise InvalidCursor(
                f"this cursor pages a listing ordered by {payload['o']}, not {order}: "
                "pass the same changed_since (or none) as the request that returned it")
        key = payload["k"]
        if order == LISTING_ORDER_ID:
            (alert_id,) = key
            return [int(alert_id)]
        updated_at, alert_id = key
        return [datetime.fromisoformat(updated_at), int(alert_id)]

    return decode_cursor(cursor, parse)


def fetch_alert_page(
    listing: AlertListing, cursor: str | None, limit: int
) -> tuple[list[AlertListRow], str | None]:
    """One page of the listing after `cursor` (the first page when None), and the cursor of
    the next page (None on the last). Raises InvalidCursor."""
    alert_ids, next_cursor = fetch_alert_page_ids(listing, cursor, limit)
    return load_alert_list_rows(alert_ids), next_cursor


def fetch_alert_page_ids(
    listing: AlertListing, cursor: str | None, limit: int
) -> tuple[list[int], str | None]:
    """The alert ids of one page of the listing, in page order, and the cursor of the next
    page: fetch_alert_page() without the rows, for callers that load their own. Raises
    InvalidCursor."""
    statement = listing.statement
    if listing.order == LISTING_ORDER_UPDATED:
        # only rows no open transaction can still be writing (aceapi_v2.common.listing)
        statement = statement.where(settled(Alert.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
        if cursor is not None:
            updated_at, alert_id = decode_listing_cursor(cursor, listing.order)
            # written out rather than as a row comparison so mysql serves it from the index
            statement = statement.where(or_(
                Alert.updated_at > updated_at,
                and_(Alert.updated_at == updated_at, Alert.id > alert_id)))
        statement = statement.order_by(Alert.updated_at, Alert.id)
    else:
        if cursor is not None:
            (alert_id,) = decode_listing_cursor(cursor, listing.order)
            statement = statement.where(Alert.id > alert_id)
        statement = statement.order_by(Alert.id)

    keys = get_db().execute(statement.limit(limit + 1)).all()
    next_cursor = None
    if len(keys) > limit:
        keys = keys[:limit]
        last_id, last_updated_at = keys[-1]
        next_cursor = encode_listing_cursor(listing.order, last_id, last_updated_at)

    return [alert_id for alert_id, _ in keys], next_cursor


def count_alert_listing(listing: AlertListing) -> int:
    """How many alerts the listing matches."""
    return get_db().execute(select(func.count()).select_from(listing.statement.subquery())).scalar_one()


def load_alert_rows(alert_ids: list[int]) -> list[AlertRow]:
    """The rows for these alert ids, in the order given: a fixed number of queries, whatever the
    page size."""
    if not alert_ids:
        return []

    db = get_db()
    owner = aliased(User)
    disposition_user = aliased(User)
    result = db.execute(
        select(
            Alert.id, Alert.uuid, Alert.insert_date, Alert.event_time, Alert.disposition_time,
            Alert.owner_time, Alert.updated_at, Alert.tool, Alert.tool_instance, Alert.alert_type,
            Alert.description, Alert.priority, Alert.queue, Alert.disposition,
            disposition_user.username, owner.username, Company.name, Alert.location, Alert.archived,
        )
        .outerjoin(owner, owner.id == Alert.owner_id)
        .outerjoin(disposition_user, disposition_user.id == Alert.disposition_user_id)
        .outerjoin(Company, Company.id == Alert.company_id)
        .where(Alert.id.in_(alert_ids))
    ).all()

    tags: dict[int, list[str]] = {}
    for alert_id, name in db.execute(
        select(TagMapping.alert_id, Tag.name)
        .join(Tag, Tag.id == TagMapping.tag_id)
        .where(TagMapping.alert_id.in_(alert_ids))
    ):
        tags.setdefault(alert_id, []).append(name)

    detection_counts = dict(db.execute(
        select(DetectionPoint.alert_id, func.count())
        .where(DetectionPoint.alert_id.in_(alert_ids))
        .group_by(DetectionPoint.alert_id)
    ).all())

    svs = alert_svs_statuses({row[0]: row[1] for row in result})

    rows = {}
    for (alert_id, alert_uuid, insert_date, event_time, disposition_time, owner_time, updated_at,
         tool, tool_instance, alert_type, description, priority, queue, disposition,
         disposition_username, owner_username, company_name, location, archived) in result:
        rows[alert_id] = AlertRow(
            uuid=alert_uuid,
            insert_date=insert_date,
            event_time=event_time,
            disposition_time=disposition_time,
            owner_time=owner_time,
            updated_at=updated_at,
            tool=tool,
            tool_instance=tool_instance,
            alert_type=alert_type,
            description=description,
            priority=priority,
            queue=queue,
            disposition=disposition,
            disposition_user=disposition_username,
            owner=owner_username,
            company=company_name,
            location=location,
            archived=bool(archived),
            tags=sorted(tags.get(alert_id, [])),
            detection_count=detection_counts.get(alert_id, 0),
            svs_status=svs[alert_id].status.value if alert_id in svs else None,
            svs_runs=list(svs[alert_id].runs) if alert_id in svs else [],
        )

    # an alert deleted between the key query and this one is simply absent
    return [rows[alert_id] for alert_id in alert_ids if alert_id in rows]


def load_alert_list_rows(alert_ids: list[int]) -> list[AlertListRow]:
    """The listing's rows for these alert ids, in the order given: load_alert_rows() plus the
    comments on each alert, in one more query."""
    rows = load_alert_rows(alert_ids)
    if not rows:
        return []

    comments: dict[str, list[str]] = {}
    for alert_uuid, comment in get_db().execute(
        select(Comment.uuid, Comment.comment)
        .where(Comment.uuid.in_([row.uuid for row in rows]))
        .order_by(Comment.insert_date, Comment.comment_id)
    ):
        comments.setdefault(alert_uuid, []).append(comment)

    return [AlertListRow(**row.model_dump(), comments=comments.get(row.uuid, [])) for row in rows]


def alert_rows_to_csv(rows: list[AlertListRow], *, header: bool) -> str:
    """CSV text for rows of the export, with the header line when asked."""
    def flatten(values: dict) -> None:
        values["tags"] = ",".join(values["tags"])
        values["svs_runs"] = ",".join(values["svs_runs"])
        # a comment can hold commas; the csv module quotes the newlines
        values["comments"] = "\n".join(values["comments"])

    return rows_to_csv(rows, ALERT_ROW_CSV_FIELDS, header=header, flatten=flatten)
