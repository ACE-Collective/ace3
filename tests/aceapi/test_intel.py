import pytest
import datetime
import base64
import json
import uuid

from aceapi.auth import set_user_api_key
from aceapi.intel import (
    KEY_ERROR,
    KEY_IDS,
    KEY_VALUES,
    KEY_B64VALUES,
    KEY_TYPES,
    KEY_FOR_DETECTION,
    KEY_EXPIRED,
    KEY_FA_HITS,
    KEY_DETECTION_MODIFIED_BY_NAMES,
    KEY_DETECTION_MODIFIED_BY_IDS,
    KEY_BATCH_IDS,
    KEY_ALERT_IDS,
    KEY_ALERT_UUIDS,
    KEY_EVENT_IDS,
    KEY_RESULTS,
    KEY_LIMIT,
    KEY_OFFSET,
    KEY_UPDATES,
    KEY_UPDATE_ID,
    KEY_UPDATE_TYPE,
    KEY_UPDATE_VALUE,
    KEY_UPDATE_B64VALUE,
    KEY_UPDATE_FOR_DETECTION,
    KEY_UPDATE_DETECTION_CONTEXT,
    KEY_UPDATE_EXPIRES_ON,
    KEY_UPDATE_BATCH_ID,
)
from saq.analysis import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import F_IP, F_FQDN
from saq.database import Observable, ObservableDetection, User, Alert, Event, ALERT

from flask import url_for

from saq.database.pool import get_db
from tests.saq.helpers import create_root_analysis


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def _post(test_client, updates: list[dict], client_kwargs: dict):
    return test_client.post(
        url_for('intel.set_observables'),
        data={KEY_UPDATES: json.dumps({KEY_UPDATES: updates})},
        **client_kwargs)


def _get(test_client, client_kwargs: dict, **query):
    result = test_client.get(url_for('intel.get_observables'), query_string=query, **client_kwargs)
    assert result.status_code == 200
    return json.loads(result.data)


@pytest.fixture
def api_client_kwargs():
    return {"headers": {'x-ace-auth': get_config().api.api_key}}


@pytest.mark.integration
def test_set_observable_by_type_and_value(test_client, api_client_kwargs):
    """A detection is created from a type and value, with no observables row involved."""
    _detection_context = str(uuid.uuid4())
    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN,
        KEY_UPDATE_VALUE: "evil.com",
        KEY_UPDATE_FOR_DETECTION: 1,
        KEY_UPDATE_DETECTION_CONTEXT: _detection_context,
    }], api_client_kwargs)

    get_db().close()
    detection = get_db().query(ObservableDetection).filter(
        ObservableDetection.type == F_FQDN, ObservableDetection.value == "evil.com").one()
    assert detection.detection_context == _detection_context

    # the observables index was not touched -- that table is the ingest path's
    assert get_db().query(Observable).filter(Observable.type == F_FQDN).count() == 0


@pytest.mark.integration
def test_set_observable_creates_detection_for_never_seen_value(test_client, api_client_kwargs):
    """The capability the old design could not express: no alert has ever contained this value."""
    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN,
        KEY_UPDATE_VALUE: "never-seen.example.com",
        KEY_UPDATE_FOR_DETECTION: 1,
    }], api_client_kwargs)

    get_db().close()
    assert get_db().query(ObservableDetection).filter(
        ObservableDetection.value == "never-seen.example.com").count() == 1


@pytest.mark.integration
def test_set_observable_by_b64value(test_client, api_client_kwargs):
    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN,
        KEY_UPDATE_B64VALUE: _b64("b64.example.com"),
        KEY_UPDATE_FOR_DETECTION: 1,
    }], api_client_kwargs)

    get_db().close()
    assert get_db().query(ObservableDetection).filter(
        ObservableDetection.value == "b64.example.com").count() == 1


@pytest.mark.integration
def test_set_observable_by_id(test_client, api_client_kwargs):
    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "byid.example.com", KEY_UPDATE_FOR_DETECTION: 1,
    }], api_client_kwargs)
    get_db().close()

    detection_id = get_db().query(ObservableDetection).filter(
        ObservableDetection.value == "byid.example.com").one().id

    _batch_id = str(uuid.uuid4())
    _post(test_client, [{
        KEY_UPDATE_ID: detection_id,
        KEY_UPDATE_EXPIRES_ON: "2030-01-01 00:00:00",
        KEY_UPDATE_DETECTION_CONTEXT: "updated",
        KEY_UPDATE_BATCH_ID: _batch_id,
    }], api_client_kwargs)

    get_db().close()
    detection = get_db().query(ObservableDetection).filter(ObservableDetection.id == detection_id).one()
    assert detection.detection_context == "updated"
    assert detection.expires_on == datetime.datetime(2030, 1, 1, 0, 0, 0)
    assert detection.batch_id == _batch_id


@pytest.mark.integration
def test_set_observable_disable_deletes_the_detection(test_client, api_client_kwargs):
    """A row is an active detection, so for_detection=0 removes it."""
    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "gone.example.com", KEY_UPDATE_FOR_DETECTION: 1,
    }], api_client_kwargs)
    get_db().close()
    assert get_db().query(ObservableDetection).filter(
        ObservableDetection.value == "gone.example.com").count() == 1

    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "gone.example.com", KEY_UPDATE_FOR_DETECTION: 0,
    }], api_client_kwargs)
    get_db().close()
    assert get_db().query(ObservableDetection).filter(
        ObservableDetection.value == "gone.example.com").count() == 0


@pytest.mark.integration
def test_set_observable_multiple_updates(test_client, api_client_kwargs):
    _batch_id = str(uuid.uuid4())
    _post(test_client, [
        {KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "one.example.com",
         KEY_UPDATE_FOR_DETECTION: 1, KEY_UPDATE_BATCH_ID: _batch_id},
        {KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "two.example.com",
         KEY_UPDATE_FOR_DETECTION: 1, KEY_UPDATE_BATCH_ID: _batch_id},
    ], api_client_kwargs)

    get_db().close()
    assert get_db().query(ObservableDetection).filter(
        ObservableDetection.batch_id == _batch_id).count() == 2


@pytest.mark.integration
def test_set_observable_rejects_an_invalid_value(test_client, api_client_kwargs):
    result = _post(test_client, [{
        KEY_UPDATE_TYPE: "ipv4", KEY_UPDATE_VALUE: "notanip", KEY_UPDATE_FOR_DETECTION: 1,
    }], api_client_kwargs)

    assert json.loads(result.data)[KEY_ERROR] is not None
    get_db().close()
    assert get_db().query(ObservableDetection).count() == 0


@pytest.mark.integration
def test_set_observable_rejects_non_utf8_b64value(test_client, api_client_kwargs):
    """Bytes that cannot round-trip through text could never match at runtime, so they are refused
    rather than silently stored lossily."""
    result = _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN,
        KEY_UPDATE_B64VALUE: base64.b64encode(b"\xff\xfe\x00bad").decode(),
        KEY_UPDATE_FOR_DETECTION: 1,
    }], api_client_kwargs)

    assert json.loads(result.data)[KEY_ERROR] is not None


@pytest.mark.integration
def test_set_observable_rejects_expires_on_true(test_client, api_client_kwargs):
    """`true` meant "reset to the per-type default", which was the ingest-expiration concept.

    A detection's expiration is only ever set explicitly now, so this fails loudly instead of being
    reinterpreted.
    """
    result = _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN,
        KEY_UPDATE_VALUE: "reset.example.com",
        KEY_UPDATE_EXPIRES_ON: True,
    }], api_client_kwargs)

    assert json.loads(result.data)[KEY_ERROR] is not None


@pytest.mark.integration
def test_set_observable_expires_on_false_clears(test_client, api_client_kwargs):
    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "clear.example.com",
        KEY_UPDATE_FOR_DETECTION: 1, KEY_UPDATE_EXPIRES_ON: "2030-01-01 00:00:00",
    }], api_client_kwargs)
    get_db().close()

    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "clear.example.com", KEY_UPDATE_EXPIRES_ON: False,
    }], api_client_kwargs)
    get_db().close()

    detection = get_db().query(ObservableDetection).filter(
        ObservableDetection.value == "clear.example.com").one()
    assert detection.expires_on is None


@pytest.mark.integration
def test_set_observable_as_user(test_client):
    user = get_db().query(User).first()
    client_kwargs = {"headers": {'x-ace-auth': set_user_api_key(user.id)}}
    user_id = user.id
    get_db().close()

    _post(test_client, [{
        KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "byuser.example.com", KEY_UPDATE_FOR_DETECTION: 1,
    }], client_kwargs)

    get_db().close()
    detection = get_db().query(ObservableDetection).filter(
        ObservableDetection.value == "byuser.example.com").one()
    assert detection.created_by == user_id
    assert detection.modified_by == user_id


@pytest.mark.integration
def test_get_observable(test_client, api_client_kwargs):
    json_result = _get(test_client, api_client_kwargs)
    assert KEY_RESULTS in json_result
    assert KEY_ERROR in json_result
    assert json_result[KEY_RESULTS] == []
    assert json_result[KEY_ERROR] is None

    # create an alert whose observable is also a detection, so the LEFT JOIN has something to find
    alert_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=alert_uuid)
    root.add_observable_by_spec(F_IP, "1.2.3.4")
    root.save()
    ALERT(root)
    get_db().close()

    _post(test_client, [
        {KEY_UPDATE_TYPE: F_IP, KEY_UPDATE_VALUE: "1.2.3.4", KEY_UPDATE_FOR_DETECTION: 1},
        {KEY_UPDATE_TYPE: F_IP, KEY_UPDATE_VALUE: "1.2.3.5", KEY_UPDATE_FOR_DETECTION: 1},
        {KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "other.example.com", KEY_UPDATE_FOR_DETECTION: 1},
    ], api_client_kwargs)
    get_db().close()

    # query all
    json_result = _get(test_client, api_client_kwargs)
    assert len(json_result[KEY_RESULTS]) == 3

    by_value = {base64.b64decode(r["value"]).decode(): r for r in json_result[KEY_RESULTS]}
    seen = by_value["1.2.3.4"]
    unseen = by_value["1.2.3.5"]

    # the detection whose value is in an alert carries the joined observables row; the other does not
    assert seen["observable_id"] is not None
    assert unseen["observable_id"] is None
    assert seen["for_detection"] is True

    detection_id = seen["id"]

    # query id
    json_result = _get(test_client, api_client_kwargs, **{KEY_IDS: detection_id})
    assert len(json_result[KEY_RESULTS]) == 1
    assert json_result[KEY_RESULTS][0]["id"] == detection_id

    # unknown id
    json_result = _get(test_client, api_client_kwargs, **{KEY_IDS: 999999})
    assert len(json_result[KEY_RESULTS]) == 0

    # limit and offset
    all_ids = [r["id"] for r in _get(test_client, api_client_kwargs)[KEY_RESULTS]]
    json_result = _get(test_client, api_client_kwargs, **{KEY_LIMIT: "1", KEY_OFFSET: "0"})
    assert [r["id"] for r in json_result[KEY_RESULTS]] == [all_ids[0]]
    json_result = _get(test_client, api_client_kwargs, **{KEY_LIMIT: "1", KEY_OFFSET: "1"})
    assert [r["id"] for r in json_result[KEY_RESULTS]] == [all_ids[1]]
    json_result = _get(test_client, api_client_kwargs, **{KEY_LIMIT: "1", KEY_OFFSET: "99"})
    assert len(json_result[KEY_RESULTS]) == 0

    # query value
    json_result = _get(test_client, api_client_kwargs, **{KEY_VALUES: "1.2.3.4"})
    assert [r["id"] for r in json_result[KEY_RESULTS]] == [detection_id]

    json_result = _get(test_client, api_client_kwargs, **{KEY_VALUES: "1.2.3.3"})
    assert len(json_result[KEY_RESULTS]) == 0

    json_result = _get(test_client, api_client_kwargs, **{KEY_VALUES: "1.2.3.4,1.2.3.5"})
    assert len(json_result[KEY_RESULTS]) == 2

    # query base64 value
    json_result = _get(test_client, api_client_kwargs, **{KEY_B64VALUES: _b64("1.2.3.4")})
    assert [r["id"] for r in json_result[KEY_RESULTS]] == [detection_id]

    json_result = _get(test_client, api_client_kwargs,
                       **{KEY_B64VALUES: ",".join([_b64("1.2.3.4"), _b64("1.2.3.5")])})
    assert len(json_result[KEY_RESULTS]) == 2

    # query type
    json_result = _get(test_client, api_client_kwargs, **{KEY_TYPES: F_IP})
    assert len(json_result[KEY_RESULTS]) == 2

    # query type and value
    json_result = _get(test_client, api_client_kwargs, **{KEY_TYPES: F_IP, KEY_VALUES: "1.2.3.4"})
    assert len(json_result[KEY_RESULTS]) == 1

    # every row is an active detection
    json_result = _get(test_client, api_client_kwargs, **{KEY_FOR_DETECTION: "1"})
    assert len(json_result[KEY_RESULTS]) == 3
    json_result = _get(test_client, api_client_kwargs, **{KEY_FOR_DETECTION: "0"})
    assert len(json_result[KEY_RESULTS]) == 0

    # query for expired
    json_result = _get(test_client, api_client_kwargs, **{KEY_EXPIRED: "1"})
    assert len(json_result[KEY_RESULTS]) == 0

    detection = get_db().query(ObservableDetection).filter(ObservableDetection.id == detection_id).one()
    detection.expires_on = datetime.datetime.now() - datetime.timedelta(days=1)
    get_db().commit()

    json_result = _get(test_client, api_client_kwargs, **{KEY_EXPIRED: "1"})
    assert len(json_result[KEY_RESULTS]) == 1

    # fa_hits comes from the joined observables row, so only the seen detection can have one
    json_result = _get(test_client, api_client_kwargs, **{KEY_FA_HITS: "null"})
    assert len(json_result[KEY_RESULTS]) == 3

    observable = get_db().query(Observable).filter(Observable.type == F_IP).one()
    observable.fa_hits = 0
    get_db().commit()

    assert len(_get(test_client, api_client_kwargs, **{KEY_FA_HITS: "false"})[KEY_RESULTS]) == 1

    observable.fa_hits = 1
    get_db().commit()

    assert len(_get(test_client, api_client_kwargs, **{KEY_FA_HITS: "true"})[KEY_RESULTS]) == 1
    assert len(_get(test_client, api_client_kwargs, **{KEY_FA_HITS: ">0"})[KEY_RESULTS]) == 1
    assert len(_get(test_client, api_client_kwargs, **{KEY_FA_HITS: "<2"})[KEY_RESULTS]) == 1
    assert len(_get(test_client, api_client_kwargs, **{KEY_FA_HITS: "1"})[KEY_RESULTS]) == 1

    # query by who last modified the detection
    user = get_db().query(User).first()
    assert len(_get(test_client, api_client_kwargs,
                    **{KEY_DETECTION_MODIFIED_BY_NAMES: user.username})[KEY_RESULTS]) == 0

    detection = get_db().query(ObservableDetection).filter(ObservableDetection.id == detection_id).one()
    detection.modified_by = user.id
    get_db().commit()

    assert len(_get(test_client, api_client_kwargs,
                    **{KEY_DETECTION_MODIFIED_BY_NAMES: user.username})[KEY_RESULTS]) == 1
    assert len(_get(test_client, api_client_kwargs,
                    **{KEY_DETECTION_MODIFIED_BY_IDS: user.id})[KEY_RESULTS]) == 1

    # query by batch id
    batch_id = str(uuid.uuid4())
    assert len(_get(test_client, api_client_kwargs, **{KEY_BATCH_IDS: batch_id})[KEY_RESULTS]) == 0

    detection = get_db().query(ObservableDetection).filter(ObservableDetection.id == detection_id).one()
    detection.batch_id = batch_id
    get_db().commit()

    assert len(_get(test_client, api_client_kwargs, **{KEY_BATCH_IDS: batch_id})[KEY_RESULTS]) == 1

    # the alert/event filters go through observable_mapping, so they can only ever match a detection
    # whose value has actually been seen
    alert = get_db().query(Alert).filter(Alert.uuid == alert_uuid).one()

    json_result = _get(test_client, api_client_kwargs, **{KEY_ALERT_IDS: alert.id})
    assert [r["id"] for r in json_result[KEY_RESULTS]] == [detection_id]

    json_result = _get(test_client, api_client_kwargs, **{KEY_ALERT_UUIDS: alert.uuid})
    assert [r["id"] for r in json_result[KEY_RESULTS]] == [detection_id]

    from saq.database import (
        EventStatus, EventRemediation, EventVector, EventRiskLevel, EventPreventionTool, EventType,
        EventMapping,
    )
    get_db().add(EventStatus(id=1, value="test"))
    get_db().add(EventRemediation(id=1, value="test"))
    get_db().add(EventVector(id=1, value="test"))
    get_db().add(EventRiskLevel(id=1, value="test"))
    get_db().add(EventPreventionTool(id=1, value="test"))
    get_db().add(EventType(id=1, value="test"))
    get_db().add(Event(id=1, creation_date=datetime.datetime.now(), name="test", status_id=1,
                       remediation_id=1, vector_id=1, risk_level_id=1, prevention_tool_id=1, type_id=1))
    get_db().commit()

    alert = get_db().query(Alert).filter(Alert.uuid == alert_uuid).one()
    get_db().add(EventMapping(alert_id=alert.id, event_id=1))
    get_db().commit()

    json_result = _get(test_client, api_client_kwargs, **{KEY_EVENT_IDS: "1"})
    assert [r["id"] for r in json_result[KEY_RESULTS]] == [detection_id]
