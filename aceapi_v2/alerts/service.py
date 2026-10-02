"""Alert service for ACE API v2."""

import base64
import csv
import io
import json
import logging
import os
import shutil
import tempfile
import uuid as uuidlib
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, and_, func, or_, select, text
from sqlalchemy.orm import aliased

from saq.constants import ANALYSIS_MODE_CORRELATION, VALID_DIRECTIVES
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
from saq.database.util.alert import node_scope_locations
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload
from saq.environment import get_base_dir, get_temp_dir
from saq.gui.alert import GUIAlert
from saq.gui.filter_query import resolve_filter_list, uses_filter_sentinels
from saq.gui.filter_screens import ALERTS_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.json_encoding import _JSONEncoder
from saq.search.query import build_listing_query
from saq.search.types import SearchFilters
from saq.util import local_time
from saq.util.uuid import is_uuid

from aceapi_v2.alerts.schemas import ALERT_ROW_CSV_FIELDS, AlertRow, BulkAddObservableResult
from aceapi_v2.common.archive import ZIP_PASSWORD, add_to_encrypted_zip
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

LISTING_MAX_PAGE_SIZE = 1000
LISTING_EXPORT_PAGE_SIZE = 1000

# A changed_since pull only returns rows whose updated_at is at least this old. updated_at is
# stamped when the UPDATE runs, not when it commits, so a row can appear with a timestamp
# older than a cursor that was already handed out; waiting until no transaction can still be
# writing a value that old is what makes the (updated_at, id) keyset safe. Delivery is
# at-least-once: a client that resumes from changed_since may see a row twice, never miss one.
CHANGED_SINCE_SETTLE_SECONDS = 5

_CURSOR_VERSION = 1


class InvalidListingRequest(ValueError):
    """The filters of a listing request cannot be used; detail is a message or pydantic errors."""

    def __init__(self, detail):
        super().__init__(str(detail))
        self.detail = detail


class InvalidCursor(ValueError):
    """The cursor is malformed, or belongs to a listing in another order."""


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
    payload = json.dumps({"v": _CURSOR_VERSION, "o": order, "k": key}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def decode_listing_cursor(cursor: str, order: str) -> list:
    """The keyset values a cursor carries. Raises InvalidCursor."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if payload["v"] != _CURSOR_VERSION:
            raise InvalidCursor(f"unsupported cursor version {payload['v']!r}")
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
    except InvalidCursor:
        raise
    except Exception as e:
        raise InvalidCursor(f"malformed cursor: {e}") from None


def fetch_alert_page(
    listing: AlertListing, cursor: str | None, limit: int
) -> tuple[list[AlertRow], str | None]:
    """One page of the listing after `cursor` (the first page when None), and the cursor of
    the next page (None on the last). Raises InvalidCursor."""
    statement = listing.statement
    if listing.order == LISTING_ORDER_UPDATED:
        settled = func.timestampadd(text("MICROSECOND"), -CHANGED_SINCE_SETTLE_SECONDS * 1000000, func.now(6))
        statement = statement.where(Alert.updated_at < settled)
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

    return load_alert_rows([alert_id for alert_id, _ in keys]), next_cursor


def load_alert_rows(alert_ids: list[int]) -> list[AlertRow]:
    """The rows for these alert ids, in the order given: three queries, whatever the page size."""
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
        )

    # an alert deleted between the key query and this one is simply absent
    return [rows[alert_id] for alert_id in alert_ids if alert_id in rows]


def alert_rows_to_csv(rows: list[AlertRow], *, header: bool) -> str:
    """CSV text for rows of the export, with the header line when asked."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if header:
        writer.writerow(ALERT_ROW_CSV_FIELDS)
    for row in rows:
        values = row.model_dump(mode="json")
        values["tags"] = ",".join(row.tags)
        writer.writerow([values[name] if values[name] is not None else "" for name in ALERT_ROW_CSV_FIELDS])
    return buffer.getvalue()
