"""Intel API (v1): manage the observables ACE alerts on.

This reads and writes the ``observable_detections`` table. It used to operate on
``observables.for_detection``; detections now have their own table, so a detection can be created
for a value that has never appeared in an alert without adding a row to the observables index.

Fields that belong to the *observable* rather than the detection (``observable_id``, ``fa_hits``)
come from a LEFT JOIN and are null when the value has not been seen.
"""

import datetime
import base64
import json
import logging
from typing import Optional

from aceapi.blueprints import intel_bp
from aceapi.auth import api_auth_check, verify_api_key, API_HEADER_NAME, API_AUTH_TYPE_USER
from aceapi.json import json_result
from saq.database import Observable, ObservableMapping, EventMapping, User, Alert, ObservableDetection
from saq.database.util.observable_detection import (
    InvalidDetectionValue,
    default_detection_expiration,
    resolve_detection_identity,
)

from flask import request
from sqlalchemy import func

from saq.database.pool import get_db

KEY_IDS = "ids"
KEY_TYPES = "types"
KEY_VALUES = "values"
KEY_B64VALUES = "b64values"
KEY_FOR_DETECTION = "for_detection"
KEY_EXPIRED = "expired"
KEY_FA_HITS = "fa_hits"
KEY_DETECTION_MODIFIED_BY_IDS = "detection_modified_by_ids"
KEY_DETECTION_MODIFIED_BY_NAMES = "detection_modified_by_names"
KEY_BATCH_IDS = "batch_ids"
KEY_ALERT_IDS = "alert_ids"
KEY_ALERT_UUIDS = "alert_uuids"
KEY_EVENT_IDS = "event_ids"

KEY_OFFSET = "offset"
KEY_LIMIT = "limit"
KEY_RESULTS = "results"
KEY_ERROR = "error"

def _create_results(results: Optional[list[dict]]=None, error: Optional[str]=None):
    return {
        KEY_RESULTS: results if results is not None else [],
        KEY_ERROR: error,
    }

def _exact_value_match(values: list[str]):
    """An exact, case-sensitive match on the detection value.

    `value` carries a case-insensitive collation so the admin UI's search finds "EVIL.com" when the
    analyst types "evil", but uniqueness is on the binary hash -- so those really are two different
    detections. A lookup by value has to be binary, or it would return both.
    """
    return ObservableDetection.value.collate("utf8mb4_bin").in_(values)

def _decode_value(value: str, b64: Optional[bool]=False) -> str:
    """Returns the text form of a value supplied as either a plain string or base64.

    Raises InvalidDetectionValue if base64 bytes are not valid utf-8. A detection value that cannot
    round-trip through text could never match anything at runtime -- the engine looks observables up
    by an f-string key -- so this rejects rather than storing it lossily.
    """
    if not b64:
        return value

    raw = base64.b64decode(value)
    try:
        return raw.decode("utf8")
    except UnicodeDecodeError as e:
        raise InvalidDetectionValue(f"value is not valid utf-8: {e}") from e

def _detection_json(detection: ObservableDetection, observable: Optional[Observable]) -> dict:
    """The v1 wire form of a detection.

    Built explicitly rather than from ObservableDetection.json so that the v1 contract is a
    deliberate choice rather than a side effect of the model. Note that `id` is now the *detection*
    id -- `observable_id` is the observables index row, and is null for a value never seen.
    """
    return {
        "id": detection.id,
        "observable_id": observable.id if observable else None,
        "type": detection.type,
        "value": base64.b64encode(detection.value.encode("utf8")).decode(),
        "sha256": detection.value_sha256.hex(),
        # a row in observable_detections is an active detection
        "for_detection": True,
        "expires_on": detection.expires_on,
        "fa_hits": observable.fa_hits if observable else None,
        "detection_modified_by": detection.modified_by_user.json if detection.modified_by_user else None,
        "detection_context": detection.detection_context,
        "batch_id": detection.batch_id,
        "created_by": detection.created_by_user.json if detection.created_by_user else None,
        "created_at": detection.created_at,
        "modified_at": detection.modified_at,
    }

def _detection_query():
    """Detections left-joined to their observables index row (absent for never-seen values)."""
    return get_db().query(ObservableDetection, Observable).outerjoin(
        Observable,
        (Observable.type == ObservableDetection.type) & (Observable.sha256 == ObservableDetection.value_sha256))

@intel_bp.route('/observables', methods=['GET'])
@api_auth_check("observable", "read")
def get_observables():
    query = _detection_query().order_by(ObservableDetection.id)

    strip = lambda _: _.strip()

    if KEY_IDS in request.values:
        query = query.filter(ObservableDetection.id.in_(map(int, map(strip, request.values[KEY_IDS].split(",")))))

    if KEY_TYPES in request.values:
        query = query.filter(ObservableDetection.type.in_(map(strip, request.values[KEY_TYPES].split(","))))

    # These match on the value directly. They used to hash the value and compare against
    # observables.sha256, which was wrong for file observables (whose hash is unhex(value), not
    # sha256(value)) -- and is unnecessary now that the column is text.
    if KEY_VALUES in request.values:
        query = query.filter(_exact_value_match(request.values[KEY_VALUES].split(",")))

    if KEY_B64VALUES in request.values:
        try:
            values = [_decode_value(v, b64=True) for v in request.values[KEY_B64VALUES].split(",")]
        except InvalidDetectionValue as e:
            return _create_results(error=str(e))
        query = query.filter(_exact_value_match(values))

    if KEY_FOR_DETECTION in request.values:
        # A row in observable_detections is an active detection, so for_detection=0 can only ever
        # match nothing. Kept so existing callers do not error.
        if request.values[KEY_FOR_DETECTION] != "1":
            return _create_results([])

    if KEY_EXPIRED in request.values:
        if request.values[KEY_EXPIRED] == "1":
            query = query.filter(ObservableDetection.expires_on < func.NOW())
        else:
            query = query.filter(ObservableDetection.expires_on >= func.NOW())

    if KEY_FA_HITS in request.values:
        if request.values[KEY_FA_HITS].lower() == "true":
            query = query.filter(Observable.fa_hits > 0)
        elif request.values[KEY_FA_HITS].lower() == "false":
            query = query.filter(Observable.fa_hits == 0)
        elif request.values[KEY_FA_HITS].lower() == "null":
            query = query.filter(Observable.fa_hits == None)
        elif request.values[KEY_FA_HITS].startswith(">"):
            query = query.filter(Observable.fa_hits > int(request.values[KEY_FA_HITS][1:]))
        elif request.values[KEY_FA_HITS].startswith("<"):
            query = query.filter(Observable.fa_hits < int(request.values[KEY_FA_HITS][1:]))
        else:
            query = query.filter(Observable.fa_hits == int(request.values[KEY_FA_HITS]))

    if KEY_DETECTION_MODIFIED_BY_NAMES in request.values:
        subquery = get_db().query(User.id).filter(User.username.in_(map(strip, request.values[KEY_DETECTION_MODIFIED_BY_NAMES].split(","))))
        query = query.filter(ObservableDetection.modified_by.in_(subquery))

    if KEY_DETECTION_MODIFIED_BY_IDS in request.values:
        query = query.filter(ObservableDetection.modified_by.in_(map(int, request.values[KEY_DETECTION_MODIFIED_BY_IDS].split(","))))

    if KEY_BATCH_IDS in request.values:
        query = query.filter(ObservableDetection.batch_id.in_(map(strip, request.values[KEY_BATCH_IDS].split(","))))

    # The alert/event filters go through observable_mapping, so they can only match detections whose
    # value has actually been seen. A detection added ahead of its first sighting is correctly
    # excluded by them.
    if KEY_ALERT_IDS in request.values:
        subquery = get_db().query(ObservableMapping.observable_id).filter(ObservableMapping.alert_id.in_(map(int, request.values[KEY_ALERT_IDS].split(","))))
        query = query.filter(Observable.id.in_(subquery))

    if KEY_ALERT_UUIDS in request.values:
        subsubquery = get_db().query(Alert.id).filter(Alert.uuid.in_(map(strip, request.values[KEY_ALERT_UUIDS].split(","))))
        subquery = get_db().query(ObservableMapping.observable_id).filter(ObservableMapping.alert_id.in_(subsubquery))
        query = query.filter(Observable.id.in_(subquery))

    if KEY_EVENT_IDS in request.values:
        subsubquery = get_db().query(EventMapping.alert_id).filter(EventMapping.event_id.in_(map(int, request.values[KEY_EVENT_IDS].split(","))))
        subquery = get_db().query(ObservableMapping.observable_id).filter(ObservableMapping.alert_id.in_(subsubquery))
        query = query.filter(Observable.id.in_(subquery))

    offset = 0
    if KEY_OFFSET in request.values:
        offset = int(request.values[KEY_OFFSET])

    if offset:
        query = query.offset(offset)

    limit = 0
    if KEY_LIMIT in request.values:
        limit = int(request.values[KEY_LIMIT])
        if limit > 50000:
            limit = 50000

    if limit:
        query = query.limit(limit)

    results = []

    try:
        for detection, observable in query:
            results.append(_detection_json(detection, observable))

        return _create_results(results)

    except Exception as e:
        logging.error("unable to query observable detections: %s", e)
        return json_result(_create_results(error=str(e)))

KEY_UPDATES = "updates"

KEY_UPDATE_ID = "id"
KEY_UPDATE_TYPE = "type"
KEY_UPDATE_VALUE = "value"
KEY_UPDATE_B64VALUE = "b64value"

KEY_UPDATE_FOR_DETECTION = "for_detection"
KEY_UPDATE_EXPIRES_ON = "expires_on"
KEY_UPDATE_DETECTION_CONTEXT = "detection_context"
KEY_UPDATE_BATCH_ID = "batch_id"

# POST parameter "updates" =
# {
#   "updates": [ { "ids": [ 1, 2, 3 ], "for_detection", 1 } ],
# }

@intel_bp.route('/observables', methods=['POST'])
@api_auth_check("observable", "write")
def set_observables():
    updates = json.loads(request.values[KEY_UPDATES])
    logging.info("updates %s", updates)

    user = _current_api_user()
    updated_detection_ids = []

    for update_spec in updates[KEY_UPDATES]:
        try:
            detection, identity = _resolve_update_target(update_spec)
        except InvalidDetectionValue as e:
            return _create_results(error=str(e))
        except ValueError as e:
            return _create_results(error=str(e))

        requested = _requested_detection_state(update_spec)

        # A row here *is* an active detection, so disabling one removes it.
        if requested is False:
            if detection is not None:
                logging.info("observable detection type %s value %s disabled by %s",
                             detection.type, detection.value, user.username if user else "unknown")
                get_db().delete(detection)
            continue

        if detection is None:
            if identity is None:
                return _create_results(error=f"could not find detection {update_spec}")

            if requested is not True:
                return _create_results(
                    error=f"no detection exists for {identity.type} {identity.value!r}: "
                          "pass for_detection=1 to create one")

            # This is the create-for-a-never-seen-observable path. It writes nothing to the
            # observables index -- that table is owned by the ingest path.
            detection = ObservableDetection(
                type=identity.type,
                value=identity.value,
                value_sha256=identity.value_sha256,
                # the per-type default from observable_expiration_mappings; None (never expires)
                # unless configured. An explicit expires_on in the spec overwrites it below.
                expires_on=default_detection_expiration(identity.type),
                created_by=user.id if user else None)
            get_db().add(detection)

            logging.info("observable detection type %s value %s enabled by %s",
                         detection.type, detection.value, user.username if user else "unknown")

        # modified_by tracks whoever last changed the detection, matching modified_at (which MySQL
        # maintains on any update), so it is stamped for every change and not just an enable.
        detection.modified_by = user.id if user else None

        if KEY_UPDATE_EXPIRES_ON in update_spec:
            expires_on = update_spec[KEY_UPDATE_EXPIRES_ON]
            if isinstance(expires_on, str):
                # 2023-12-09 18:30:06
                detection.expires_on = datetime.datetime.strptime(expires_on, "%Y-%m-%d %H:%M:%S")
            elif expires_on is False or expires_on is None:
                detection.expires_on = None
            else:
                # `true` used to mean "reset to the configured per-type default", which was the
                # ingest-expiration concept leaking into detection management. It has no coherent
                # meaning now that a detection's expiration is only ever set explicitly.
                return _create_results(
                    error=f"invalid expires_on value {expires_on!r}: pass a 'YYYY-MM-DD HH:MM:SS' "
                          "string to set an expiration, or false to clear it")

        if KEY_UPDATE_DETECTION_CONTEXT in update_spec:
            detection.detection_context = update_spec[KEY_UPDATE_DETECTION_CONTEXT]

        if KEY_UPDATE_BATCH_ID in update_spec:
            detection.batch_id = update_spec[KEY_UPDATE_BATCH_ID]

        if not detection.id:
            get_db().flush()

        updated_detection_ids.append(detection.id)

    get_db().commit()

    results = []
    for detection, observable in _detection_query().filter(ObservableDetection.id.in_(updated_detection_ids)):
        results.append(_detection_json(detection, observable))

    return _create_results(results)

def _current_api_user() -> Optional[User]:
    """The user behind the API key on this request, when the key belongs to a user."""
    auth_result = verify_api_key(request.headers[API_HEADER_NAME])
    if not auth_result or auth_result.auth_type != API_AUTH_TYPE_USER:
        return None

    try:
        return get_db().query(User).filter(User.username == auth_result.auth_name).one()
    except Exception as e:
        logging.warning("unable to resolve the api user for an observable detection update: %s", e)
        return None

def _requested_detection_state(update_spec: dict) -> Optional[bool]:
    """The enable/disable the spec asked for, or None if it did not ask."""
    if KEY_UPDATE_FOR_DETECTION not in update_spec:
        return None

    value = update_spec[KEY_UPDATE_FOR_DETECTION]
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "")

    return bool(value)

def _resolve_update_target(update_spec: dict):
    """Resolves one update spec to (existing detection or None, identity or None).

    The identity is None when the spec addresses a detection by id, since there is nothing to create
    in that case. Raises ValueError if the spec addresses nothing.
    """
    if KEY_UPDATE_ID in update_spec:
        detection = get_db().query(ObservableDetection).filter(
            ObservableDetection.id == int(update_spec[KEY_UPDATE_ID])).one_or_none()
        if detection is None:
            raise ValueError(f"could not find detection {update_spec}")
        return detection, None

    if KEY_UPDATE_TYPE not in update_spec:
        raise ValueError(f"could not find detection {update_spec}")

    if KEY_UPDATE_VALUE in update_spec:
        value = _decode_value(update_spec[KEY_UPDATE_VALUE])
    elif KEY_UPDATE_B64VALUE in update_spec:
        value = _decode_value(update_spec[KEY_UPDATE_B64VALUE], b64=True)
    else:
        raise ValueError(f"invalid observable update dict (missing {KEY_UPDATE_VALUE} or "
                         f"{KEY_UPDATE_B64VALUE}) {update_spec}")

    # resolve_detection_identity normalizes the value and computes the hash with the polymorphic
    # Observable.sha256_bytes semantics -- for a file observable that is unhex(value), not
    # sha256(value), which this endpoint used to get wrong.
    identity = resolve_detection_identity(update_spec[KEY_UPDATE_TYPE], value)
    detection = get_db().query(ObservableDetection).filter(
        ObservableDetection.type == identity.type,
        ObservableDetection.value_sha256 == identity.value_sha256).one_or_none()

    return detection, identity
