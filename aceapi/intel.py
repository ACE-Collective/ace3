import datetime
import base64
import hashlib
import json
import logging
from typing import Optional

from aceapi.blueprints import intel_bp
from aceapi.auth import api_auth_check, verify_api_key, API_HEADER_NAME, API_AUTH_TYPE_USER
from aceapi.json import json_result
from saq.analysis.observable import get_observable_type_expiration_time
from saq.database import Observable, ObservableMapping, EventMapping, User, Alert

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
KEY_ENABLED_BY_IDS = "enabled_by_ids"
KEY_ENABLED_BY_NAMES = "enabled_by_names"
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

def _sha256_value(value: str, b64: Optional[bool]=False) -> bytes:
    if b64:
        value = base64.b64decode(value)
    else:
        value = value.encode(errors="ignore")

    hasher = hashlib.sha256()
    hasher.update(value)
    return hasher.digest()

def _sha256_values(values: str, b64: Optional[bool]=False) -> list[bytes]:
    return [_sha256_value(_, b64) for _ in values.split(",")]

@intel_bp.route('/observables', methods=['GET'])
@api_auth_check("observable", "read")
def get_observables():
    query = get_db().query(Observable).order_by(Observable.id)

    strip = lambda _: _.strip()

    if KEY_IDS in request.values:
        query = query.filter(Observable.id.in_(map(int, map(strip, request.values[KEY_IDS].split(",")))))

    if KEY_TYPES in request.values:
        query = query.filter(Observable.type.in_(map(strip, request.values[KEY_TYPES].split(","))))

    if KEY_VALUES in request.values:
        query = query.filter(Observable.sha256.in_(_sha256_values(request.values[KEY_VALUES])))

    if KEY_B64VALUES in request.values:
        query = query.filter(Observable.sha256.in_(_sha256_values(request.values[KEY_B64VALUES], b64=True)))

    if KEY_FOR_DETECTION in request.values:
        query = query.filter(Observable.for_detection == request.values[KEY_FOR_DETECTION] == "1")

    if KEY_EXPIRED in request.values:
        if request.values[KEY_EXPIRED] == "1":
            query = query.filter(Observable.expires_on < func.NOW())
        else:
            query = query.filter(Observable.expires_on >= func.NOW())

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

    if KEY_ENABLED_BY_NAMES in request.values:
        subquery = get_db().query(User.id).filter(User.username.in_(map(strip, request.values[KEY_ENABLED_BY_NAMES].split(","))))
        query = query.filter(Observable.enabled_by.in_(subquery))

    if KEY_ENABLED_BY_IDS in request.values:
        query = query.filter(Observable.enabled_by.in_(map(int, request.values[KEY_ENABLED_BY_IDS].split(","))))

    if KEY_BATCH_IDS in request.values:
        query = query.filter(Observable.batch_id.in_(map(strip, request.values[KEY_BATCH_IDS].split(","))))

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
        for observable in query:
            results.append(observable.json)

        return _create_results(results)

    except Exception as e:
        logging.error("unable to query observables: %s", e)
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
    updated_observable_ids = []

    for update_spec in updates[KEY_UPDATES]:
        observable = None
        if KEY_UPDATE_ID in update_spec:
            observable = get_db().query(Observable).filter(Observable.id == int(update_spec[KEY_UPDATE_ID])).one_or_none()
        elif KEY_UPDATE_TYPE in update_spec and KEY_UPDATE_VALUE in update_spec:
            observable = get_db().query(Observable).filter(Observable.type == update_spec[KEY_UPDATE_TYPE], Observable.sha256 == _sha256_value(update_spec[KEY_UPDATE_VALUE])).one_or_none()
        elif KEY_UPDATE_TYPE in update_spec and KEY_UPDATE_B64VALUE in update_spec:
            observable = get_db().query(Observable).filter(Observable.type == update_spec[KEY_UPDATE_TYPE], Observable.sha256 == _sha256_value(update_spec[KEY_UPDATE_B64VALUE], b64=True)).one_or_none()
        else:
            return _create_results(error=f"could not find observable {update_spec}")
            #logging.error("invalid observable update dict %s", update_spec)
            #abort(404)

        if observable is None:
            if KEY_UPDATE_VALUE in update_spec:
                value = update_spec[KEY_UPDATE_VALUE].encode()
            elif KEY_UPDATE_B64VALUE in update_spec:
                value = base64.b64decode(update_spec.get(KEY_UPDATE_B64VALUE))
            else:
                logging.error("invalid observable update dict (missing %s or %s) %s", KEY_UPDATE_VALUE, KEY_UPDATE_B64VALUE, update_spec)
                return _create_results(error="invalid observable update dict")

            # if expires on is not set it defaults to system settings
            if KEY_UPDATE_EXPIRES_ON in update_spec:
                expires_on = datetime.datetime.strptime(update_spec[KEY_UPDATE_EXPIRES_ON], "%Y-%m-%d %H:%M:%S")
            else:
                expires_on = get_observable_type_expiration_time(update_spec[KEY_UPDATE_TYPE])

            observable = Observable(type=update_spec[KEY_UPDATE_TYPE], value=value, sha256=_sha256_value(value.decode()), expires_on=expires_on)

        if KEY_UPDATE_FOR_DETECTION in update_spec:
            observable.for_detection = update_spec[KEY_UPDATE_FOR_DETECTION]
            if observable.for_detection:
                auth_result = verify_api_key(request.headers[API_HEADER_NAME])
                if auth_result and auth_result.auth_type == API_AUTH_TYPE_USER:
                    try:
                        user = get_db().query(User).filter(User.username == auth_result.auth_name).one()
                        observable.enabled_by = user.id
                        logging.info("observable detection type %s value %s enabled by %s", observable.type, observable.value, user.username)
                    except Exception as e:
                        logging.warning("unable to set enabled_by for observable detection: %s", e)

        if KEY_UPDATE_EXPIRES_ON in update_spec:
            # 2023-12-09 18:30:06
            if isinstance(update_spec[KEY_UPDATE_EXPIRES_ON], str):
                observable.expires_on = datetime.datetime.strptime(update_spec[KEY_UPDATE_EXPIRES_ON], "%Y-%m-%d %H:%M:%S")
            elif isinstance(update_spec[KEY_UPDATE_EXPIRES_ON], bool):
                if update_spec[KEY_UPDATE_EXPIRES_ON]:
                    observable.expires_on = get_observable_type_expiration_time(observable.type)
                else:
                    observable.expires_on = None
            else:
                return _create_results(error=f"invalid expires_on value {update_spec}")

        if KEY_UPDATE_DETECTION_CONTEXT in update_spec:
            observable.detection_context = update_spec[KEY_UPDATE_DETECTION_CONTEXT]

        if KEY_UPDATE_BATCH_ID in update_spec:
            observable.batch_id = update_spec[KEY_UPDATE_BATCH_ID]

        get_db().add(observable)
        if not observable.id:
            get_db().flush()

        updated_observable_ids.append(observable.id)

    get_db().commit()

    results = []
    for observable in get_db().query(Observable).filter(Observable.id.in_(updated_observable_ids)):
        results.append(observable.json)

    return _create_results(results)
