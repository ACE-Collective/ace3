"""Management of the observables ACE alerts on.

Detections live in their own ``observable_detections`` table, deliberately separate from the
``observables`` index. See :class:`saq.database.model.ObservableDetection` for why.

Everything that creates or looks up a detection goes through :func:`resolve_detection_identity`, so
that a detection's stored ``value`` is exactly the normalized value the analysis engine will
produce at runtime, and its ``value_sha256`` uses the polymorphic ``Observable.sha256_bytes``
semantics (which for a file observable is ``unhex(value)``, not ``sha256(value)``).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import NamedTuple, Optional

from sqlalchemy import or_

from saq.analysis.observable import Observable, get_observable_type_expiration_time
from saq.analysis.root import RootAnalysis
from saq.constants import F_FILE, MAX_DETECTION_VALUE_LENGTH
from saq.database.model import ObservableDetection as DBObservableDetection, User
from saq.database.pool import get_db
from saq.observables.generator import create_observable


class InvalidDetectionValue(ValueError):
    """The given type/value pair cannot be stored as a detection."""


class DetectionIdentity(NamedTuple):
    """The normalized identity of a detection: what gets stored and matched on."""
    type: str
    value: str
    value_sha256: bytes


def resolve_detection_identity(observable_type: str, observable_value: str) -> DetectionIdentity:
    """Normalizes and validates a type/value pair into what a detection row stores.

    Raises InvalidDetectionValue if the value is not valid for the type, is too long, or is not
    representable as text.

    This runs the value through the real observable class, which is what makes a detection actually
    fire: the analysis engine looks the observable up in redis under f"{type}:{value}" using the
    *normalized* in-memory value, so storing a raw un-normalized string would produce a detection
    that silently never matches.
    """
    if observable_type == F_FILE:
        return _file_detection_identity(observable_value)

    try:
        observable = create_observable(observable_type, observable_value)
    except Exception as e:
        # a type whose constructor needs more than a value, or rejects one outright. This is an API
        # boundary, so it must surface as a validation error rather than a 500.
        raise InvalidDetectionValue(
            f"{observable_value!r} is not a valid value for observable type {observable_type}: {e}") from e

    if observable is None:
        raise InvalidDetectionValue(f"{observable_value!r} is not a valid value for observable type {observable_type}")

    return _identity_from_observable(observable)


def _file_detection_identity(observable_value: str) -> DetectionIdentity:
    """The identity of a file detection, built without constructing a FileObservable.

    FileObservable requires a file_path, and a detection has none -- it identifies file *content*,
    not a location on disk. Its value is already the content sha256 hex and its sha256_bytes is
    unhex(value), so the identity is derived directly. Lowercased to match hexdigest(), which is
    what both the observables table and the runtime redis key are built from.
    """
    value = observable_value.strip().lower()
    try:
        value_sha256 = bytes.fromhex(value)
    except ValueError as e:
        raise InvalidDetectionValue(
            f"{observable_value!r} is not a valid {F_FILE} value: it must be a sha256 hex digest") from e

    if len(value_sha256) != 32:
        raise InvalidDetectionValue(
            f"{observable_value!r} is not a valid {F_FILE} value: a sha256 hex digest is 64 characters")

    return DetectionIdentity(type=F_FILE, value=value, value_sha256=value_sha256)


def _identity_from_observable(observable: Observable) -> DetectionIdentity:
    value = observable.value
    if len(value) > MAX_DETECTION_VALUE_LENGTH:
        raise InvalidDetectionValue(
            f"observable value is {len(value)} characters, which exceeds the "
            f"{MAX_DETECTION_VALUE_LENGTH} character limit for a detection")

    # The column is text, and the runtime redis key is built from a str, so a value that cannot
    # round-trip through utf-8 could never match anything. Reject it rather than storing it lossily.
    try:
        value.encode("utf8").decode("utf8")
    except UnicodeError as e:
        raise InvalidDetectionValue(f"observable value is not valid utf-8: {e}") from e

    return DetectionIdentity(type=observable.type, value=value, value_sha256=observable.sha256_bytes)


def default_detection_expiration(observable_type: str) -> Optional[datetime]:
    """How long a new detection of this type should live, per `observable_expiration_mappings`.

    Returns None -- never expires -- for a type with no mapping, which is the default configuration.

    This config setting used to be applied by *ingest* to every observable it indexed, which is what
    made observables.expires_on mean two different things. Applied here it finally matches the
    meaning its own config comment claims: how long an observable of this type lives as a detection.
    """
    return get_observable_type_expiration_time(observable_type)


def get_active_detections_by_type() -> dict[str, list[dict]]:
    """The active detections, grouped by observable type.

    This is the single source the whole detection pipeline reads: `ace
    update-for-detection-observable-cache` turns it into the redis map the analysis engine matches
    against, and `ace export-for-detect-observables` turns it into yara rules and Splunk KVStore
    entries. A detection is active when it has not expired.

    The `id` is load-bearing beyond the cache: the yara export embeds it into generated rules as
    $obsd_<id>, which FileTypeAnalyzer parses back out.

    Returns:
        {observable_type: [{'id': ..., 'value': ...}, ...]}
    """
    from saq.util.time import local_time

    detections_by_type: dict[str, list[dict]] = {}
    rows = get_db().query(
        DBObservableDetection.id, DBObservableDetection.type, DBObservableDetection.value,
    ).filter(
        or_(
            DBObservableDetection.expires_on.is_(None),
            local_time() < DBObservableDetection.expires_on,
        )
    ).all()

    for row in rows:
        detections_by_type.setdefault(row.type, []).append({'id': row.id, 'value': row.value})

    return detections_by_type


def get_observable_detection(observable_type: str, value_sha256: bytes) -> Optional[DBObservableDetection]:
    """Returns the detection for the given type and value hash, or None."""
    return get_db().query(DBObservableDetection).filter(
        DBObservableDetection.type == observable_type,
        DBObservableDetection.value_sha256 == value_sha256).one_or_none()


def get_observable_detection_for(observable: Observable) -> Optional[DBObservableDetection]:
    """Returns the detection for the given in-memory analysis observable, or None."""
    identity = _identity_from_observable(observable)
    return get_observable_detection(identity.type, identity.value_sha256)


def create_observable_detection(
        observable_type: str,
        observable_value: str,
        user_id: Optional[int],
        detection_context: Optional[str] = None,
        expires_on: Optional[datetime] = None,
        batch_id: Optional[str] = None) -> DBObservableDetection:
    """Creates (or updates, if it already exists) a detection for the given type and value.

    Unlike the observables index, this does not require the observable to have ever been seen --
    adding a detection ahead of the first sighting is the point.
    """
    identity = resolve_detection_identity(observable_type, observable_value)
    return _upsert(identity, user_id, detection_context, expires_on, batch_id)


def _upsert(
        identity: DetectionIdentity,
        user_id: Optional[int],
        detection_context: Optional[str],
        expires_on: Optional[datetime],
        batch_id: Optional[str]) -> DBObservableDetection:

    db = get_db()
    detection = get_observable_detection(identity.type, identity.value_sha256)
    if detection is None:
        detection = DBObservableDetection(
            type=identity.type,
            value=identity.value,
            value_sha256=identity.value_sha256,
            # only on insert: re-enabling an existing detection must not silently reset an
            # expiration an analyst chose
            expires_on=default_detection_expiration(identity.type),
            created_by=user_id)
        db.add(detection)

    detection.modified_by = user_id
    if detection_context is not None:
        detection.detection_context = detection_context
    if expires_on is not None:
        detection.expires_on = expires_on
    if batch_id is not None:
        detection.batch_id = batch_id

    db.commit()
    return detection


def delete_observable_detection(detection_id: int) -> bool:
    """Deletes the detection with the given id. Returns True if a row was removed."""
    db = get_db()
    deleted = db.query(DBObservableDetection).filter(DBObservableDetection.id == detection_id).delete()
    db.commit()
    return bool(deleted)


def set_observable_detection_expiration(detection_id: int, expires_on: Optional[datetime], user_id: Optional[int]) -> Optional[DBObservableDetection]:
    """Sets (or clears, with None) the expiration of a detection. Returns None if it does not exist."""
    db = get_db()
    detection = db.query(DBObservableDetection).filter(DBObservableDetection.id == detection_id).one_or_none()
    if detection is None:
        return None

    detection.expires_on = expires_on
    detection.modified_by = user_id
    db.commit()
    return detection


def enable_observable_detection(observable: Observable, detection_modified_by_user_id: int, detection_context: str) -> DBObservableDetection:
    """Enables detection for the given in-memory analysis observable."""
    db_user = get_db().query(User).filter(User.id == detection_modified_by_user_id).one_or_none()
    if db_user is None:
        raise ValueError(f"User with id {detection_modified_by_user_id} not found")

    # This deliberately does not touch the observables table. Creating an index row was a side
    # effect of the old design, where the detection flag lived on that row; the observables table is
    # owned by the ingest path.
    return _upsert(
        _identity_from_observable(observable),
        detection_modified_by_user_id,
        detection_context,
        expires_on=None,
        batch_id=None)


def disable_observable_detection(observable: Observable, detection_modified_by_user_id: int, detection_context: str) -> bool:
    """Disables detection for the given in-memory analysis observable.

    A row in observable_detections *is* an active detection, so disabling removes it. The audit
    trail for the removal is the caller's AUDIT log line.
    """
    identity = _identity_from_observable(observable)
    db = get_db()
    deleted = db.query(DBObservableDetection).filter(
        DBObservableDetection.type == identity.type,
        DBObservableDetection.value_sha256 == identity.value_sha256).delete()
    db.commit()
    return bool(deleted)


@dataclass
class ObservableDetectionSummary:
    """What the alert view needs to render an observable's detection status."""
    observable_uuid: str
    for_detection: bool
    detection_modified_by: str
    detection_context: Optional[str]


def get_all_observable_detections(alert: RootAnalysis) -> dict[str, ObservableDetectionSummary]:
    """Returns a dictionary of observable UUIDs and their detection statuses for a given alert."""
    return get_observable_detections(alert.all_observables)


def get_observable_detections(observables: list[Observable]) -> dict[str, ObservableDetectionSummary]:
    """Returns a dictionary of observable UUID -> detection status for the observables that have one.

    Observables without a detection are simply absent from the result.
    """
    detections: dict[str, ObservableDetectionSummary] = {}
    if not observables:
        return detections

    # Query by hash alone (one indexed IN), then match on type as well -- the same shape as before,
    # since a hash can be shared across types.
    hashes = {observable.sha256_bytes for observable in observables}
    db_detections = get_db().query(DBObservableDetection).filter(
        DBObservableDetection.value_sha256.in_(hashes)).all()

    for db_detection in db_detections:
        observable = _match_observable(observables, db_detection)
        if observable is None:
            continue

        detections[observable.uuid] = ObservableDetectionSummary(
            observable_uuid=observable.uuid,
            for_detection=True,
            detection_modified_by=db_detection.modified_by_user.display_name if db_detection.modified_by_user else "unknown",
            detection_context=db_detection.detection_context)

    return detections


def _match_observable(observables: list[Observable], db_detection: DBObservableDetection) -> Optional[Observable]:
    """Returns the Observable matching the given detection row on type and value hash."""
    for observable in observables:
        if observable.type == db_detection.type and observable.sha256_bytes == db_detection.value_sha256:
            return observable

    return None
