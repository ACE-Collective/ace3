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
    KEY_ENABLED_BY_NAMES,
    KEY_ENABLED_BY_IDS,
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
from saq.constants import F_IPV4, F_FQDN
from saq.database import Observable, User, Alert, Event, ALERT

from flask import url_for

from saq.database.pool import get_db
from tests.saq.helpers import create_root_analysis

@pytest.mark.integration
def test_set_observable(test_client):
    # create a new alert
    root = create_root_analysis()
    root.add_observable_by_spec(F_FQDN, "test.com")
    root.save()
    ALERT(root)

    get_db().close()

    # get the single observable
    observable = get_db().query(Observable).filter().one()
    assert observable.for_detection == 0

    # update the existing observable by id
    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { KEY_UPDATE_ID: observable.id, KEY_UPDATE_FOR_DETECTION: 1 },
            ]
        })
    }

    client_kwargs = { "headers": { 'x-ace-auth': get_config().api.api_key } }
    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()
    observable = get_db().query(Observable).filter().one()
    assert observable.for_detection == 1

    # update the existing observable by type and value
    _detection_context = str(uuid.uuid4())
    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { KEY_UPDATE_TYPE: observable.type, KEY_UPDATE_VALUE: observable.value.decode(), KEY_UPDATE_FOR_DETECTION: 0 },
            ]
        })
    }

    client_kwargs = { "headers": { 'x-ace-auth': get_config().api.api_key } }
    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()
    observable = get_db().query(Observable).filter().one()
    assert observable.for_detection == 0

    # update the existing observable by type and base64 value
    _detection_context = str(uuid.uuid4())
    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { KEY_UPDATE_TYPE: observable.type, KEY_UPDATE_B64VALUE: base64.b64encode(observable.value).decode(), KEY_UPDATE_FOR_DETECTION: 1 },
            ]
        })
    }

    client_kwargs = { "headers": { 'x-ace-auth': get_config().api.api_key } }
    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()
    observable = get_db().query(Observable).filter().one()
    assert observable.for_detection == 1

    # update everything by id
    _batch_id = str(uuid.uuid4())
    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { 
                    KEY_UPDATE_ID: observable.id, 
                    KEY_UPDATE_FOR_DETECTION: 1,
                    KEY_UPDATE_EXPIRES_ON: "2020-01-01 00:00:00",
                    KEY_UPDATE_DETECTION_CONTEXT: "test",
                    KEY_UPDATE_BATCH_ID: _batch_id,
                },
            ]
        })
    }

    client_kwargs = { "headers": { 'x-ace-auth': get_config().api.api_key } }
    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()
    observable = get_db().query(Observable).filter().one()
    observable.for_detection == 1
    observable.detection_context == "test"
    observable.expires_on == datetime.datetime(year=2020, month=1, day=1, hour=0, minute=0, second=0)
    observable.batch_id == _batch_id

    # add a new observable

    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { 
                    KEY_UPDATE_TYPE: F_FQDN,
                    KEY_UPDATE_VALUE: "evil.com",
                    KEY_UPDATE_FOR_DETECTION: 1,
                    KEY_UPDATE_BATCH_ID: _batch_id,
                },
            ]
        })
    }

    client_kwargs = { "headers": { 'x-ace-auth': get_config().api.api_key } }
    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()

    new_observable = get_db().query(Observable).filter(Observable.type == F_FQDN, Observable.value == "evil.com".encode()).one()
    assert new_observable.for_detection == 1
    assert new_observable.batch_id == _batch_id

    # update multiple observables (using both id and type/value pair)

    _batch_id = str(uuid.uuid4())
    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { 
                    KEY_UPDATE_TYPE: F_FQDN,
                    KEY_UPDATE_VALUE: "test.com",
                    KEY_UPDATE_FOR_DETECTION: 1,
                    KEY_UPDATE_BATCH_ID: _batch_id,
                },
                { 
                    KEY_UPDATE_ID: new_observable.id,
                    KEY_UPDATE_FOR_DETECTION: 1,
                    KEY_UPDATE_BATCH_ID: _batch_id,
                },
            ]
        })
    }

    client_kwargs = { "headers": { 'x-ace-auth': get_config().api.api_key } }
    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()

    observables = get_db().query(Observable).filter(Observable.batch_id == _batch_id).all()
    assert len(observables) == 2

@pytest.mark.integration
def test_set_observable_as_user(test_client):
    user = get_db().query(User).first()
    api_key = set_user_api_key(user.id)
    client_kwargs = { "headers": { 'x-ace-auth': set_user_api_key(user.id) } }

    root = create_root_analysis()
    root.add_observable_by_spec(F_FQDN, "test.com")
    root.save()
    ALERT(root)

    user_id = user.id
    get_db().close()

    # get the single observable
    observable = get_db().query(Observable).filter().one()
    assert observable.for_detection == 0

    # update the existing observable by id
    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { KEY_UPDATE_ID: observable.id, KEY_UPDATE_FOR_DETECTION: 1 },
            ]
        })
    }

    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()

    observable = get_db().query(Observable).filter(Observable.type == F_FQDN, Observable.value == "test.com".encode()).one()
    assert observable.for_detection == 1
    observable.enabled_by == user_id

    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.add_observable_by_spec(F_FQDN, "evil.com")
    root.save()
    ALERT(root)

    get_db().close()

    # update the existing observable by id
    data = {
        KEY_UPDATES: json.dumps({
            KEY_UPDATES: [
                { KEY_UPDATE_TYPE: F_FQDN, KEY_UPDATE_VALUE: "evil.com", KEY_UPDATE_FOR_DETECTION: 0 },
            ]
        })
    }

    result = test_client.post(url_for('intel.set_observables'), data=data, **client_kwargs)

    get_db().close()

    observable = get_db().query(Observable).filter(Observable.type == F_FQDN, Observable.value == "evil.com".encode()).one()
    assert observable.for_detection == 0
    assert observable.enabled_by is None

@pytest.mark.integration
def test_get_observable(test_client):
    client_kwargs = { "headers": { 'x-ace-auth': get_config().api.api_key } }

    result = test_client.get(url_for('intel.get_observables'), **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert KEY_RESULTS in json_result
    assert KEY_ERROR in json_result
    assert json_result[KEY_RESULTS] == []
    assert json_result[KEY_ERROR] is None

    root = create_root_analysis()
    root.add_observable_by_spec(F_IPV4, "1.2.3.4")
    root.save()
    ALERT(root)

    alert_uuid = root.uuid
    get_db().close()

    # query all
    result = test_client.get(url_for('intel.get_observables'), **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
    assert json_result[KEY_RESULTS][0]["type"] == F_IPV4
    assert base64.b64decode(json_result[KEY_RESULTS][0]["value"]).decode() == "1.2.3.4"

    observable_id = json_result[KEY_RESULTS][0]["id"]

    # query id
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_IDS: observable_id }, **client_kwargs)
    result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
    assert json_result[KEY_RESULTS][0]["id"] == observable_id

    # same thing but wrong id
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_IDS: observable_id + 1}, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 0

    # insert another observable
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.add_observable_by_spec(F_IPV4, "1.2.3.5")
    root.save()
    ALERT(root)

    get_db().close()

    # get the observable ids
    result = test_client.get(url_for('intel.get_observables'), **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    observable_ids = [_["id"] for _ in json_result[KEY_RESULTS]]
    assert len(observable_ids) == 2

    # query ids
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_IDS: ",".join(map(str, observable_ids)) }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 2

    # query ids with limit
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_IDS: ",".join(map(str, observable_ids)), KEY_LIMIT: "1", KEY_OFFSET: "0" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
    assert json_result[KEY_RESULTS][0]["id"] == observable_ids[0]
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_IDS: ",".join(map(str, observable_ids)), KEY_LIMIT: "1", KEY_OFFSET: "1" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
    assert json_result[KEY_RESULTS][0]["id"] == observable_ids[1]
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_IDS: ",".join(map(str, observable_ids)), KEY_LIMIT: "1", KEY_OFFSET: "2" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 0

    # query value
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_VALUES: "1.2.3.4" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
    assert json_result[KEY_RESULTS][0]["id"] == observable_id

    # query unknown value
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_VALUES: "1.2.3.3" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 0

    # query multiple values
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_VALUES: "1.2.3.4,1.2.3.5" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    len(json_result[KEY_RESULTS]) == 2
    json_result[KEY_RESULTS][0]["id"] == observable_ids[0]
    json_result[KEY_RESULTS][1]["id"] == observable_ids[1]

    # query base64 value
    b64 = lambda s: base64.b64encode(s.encode()).decode()
    
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_B64VALUES: b64("1.2.3.4") }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
    assert json_result[KEY_RESULTS][0]["id"] == observable_id

    # query multiple base64 values
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_B64VALUES: ",".join([b64("1.2.3.4"), b64("1.2.3.5")]) }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 2
    assert json_result[KEY_RESULTS][0]["id"] == observable_ids[0]
    assert json_result[KEY_RESULTS][1]["id"] == observable_ids[1]

    # insert another observable
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.add_observable_by_spec(F_FQDN, "test.com")
    root.save()
    ALERT(root)

    get_db().close()

    # query type
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_TYPES: "ipv4" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 2

    # query type and value
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_TYPES: "ipv4", KEY_VALUES: "1.2.3.4" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # query for_detection
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FOR_DETECTION: "1" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 0

    # enable observable for detection
    observable = get_db().query(Observable).filter(Observable.id == observable_id).one()
    observable.for_detection = True
    get_db().commit()

    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FOR_DETECTION: "1" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # query for expired
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_EXPIRED: "1" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 0

    # expire observable
    observable = get_db().query(Observable).filter(Observable.id == observable_id).one()
    observable.expires_on = datetime.datetime.now() - datetime.timedelta(days=1)
    get_db().commit()

    # query for expired
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_EXPIRED: "1" }, **client_kwargs)
    result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # query for fahits
    # all should be None at this point
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FA_HITS: "null" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 3

    # set fahits to 0
    observable = get_db().query(Observable).filter(Observable.id == observable_id).one()
    observable.fa_hits = 0
    get_db().commit()

    # one observable passed frequency analysis
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FA_HITS: "false" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
    
    # set fahits to 1
    observable = get_db().query(Observable).filter(Observable.id == observable_id).one()
    observable.fa_hits = 1
    get_db().commit()

    # one observable failed frequency analysis
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FA_HITS: "true" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # test >
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FA_HITS: ">0" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # test <
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FA_HITS: "<2" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # test ==
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_FA_HITS: "1" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # get a user to use
    user = get_db().query(User).first()

    # query by enabled by name
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_ENABLED_BY_NAMES: user.username }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 0

    # set the enabled by to this user
    observable = get_db().query(Observable).filter(Observable.id == observable_id).one()
    observable.enabled_by = user.id
    get_db().commit()

    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_ENABLED_BY_NAMES: user.username }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # query by user id
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_ENABLED_BY_IDS: user.id }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    batch_id = str(uuid.uuid4())

    # query by batch id
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_BATCH_IDS: batch_id }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 0

    # set the batch id
    observable = get_db().query(Observable).filter(Observable.id == observable_id).one()
    observable.batch_id = batch_id
    get_db().commit()

    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_BATCH_IDS: batch_id }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # get alert information
    alert = get_db().query(Alert).filter(Alert.uuid == alert_uuid).one()

    # query by alert id
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_ALERT_IDS: alert.id }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # query by alert uuid
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_ALERT_UUIDS: alert.uuid }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1

    # create a new event
    from saq.database import EventStatus, EventRemediation, EventVector, EventRiskLevel, EventPreventionTool, EventType, EventMapping
    get_db().add(EventStatus(id=1, value="test"))
    get_db().add(EventRemediation(id=1, value="test"))
    get_db().add(EventVector(id=1, value="test"))
    get_db().add(EventRiskLevel(id=1, value="test"))
    get_db().add(EventPreventionTool(id=1, value="test"))
    get_db().add(EventType(id=1, value="test"))
    event = Event(id=1, creation_date=datetime.datetime.now(), name="test", status_id=1, remediation_id=1, vector_id=1, risk_level_id=1, prevention_tool_id=1, type_id=1)
    get_db().add(event)
    get_db().commit()

    alert = get_db().query(Alert).filter(Alert.uuid == alert_uuid).one()
    get_db().add(EventMapping(alert_id=alert.id, event_id=1))
    get_db().commit()

    # query by event id
    result = test_client.get(url_for('intel.get_observables'), query_string={ KEY_EVENT_IDS: "1" }, **client_kwargs)
    assert result.status_code == 200
    json_result = json.loads(result.data)
    assert len(json_result[KEY_RESULTS]) == 1
