from datetime import datetime
import io
import json
import os
import shutil
import uuid
from flask import url_for
import pytest
import pytz

from saq.analysis.root import KEY_PLAYBOOK_URL
from saq.configuration.config import get_config
from saq.constants import DIRECTIVE_NO_SCAN, EVENT_TIME_FORMAT_JSON_TZ, F_FILE, F_IPV4, F_USER
from saq.database.pool import get_db_connection
from saq.environment import get_data_dir, get_global_runtime_settings, get_local_timezone
from saq.json_encoding import _JSONEncoder
from saq.util.time import parse_event_time

@pytest.mark.integration
def test_api_analysis_submit(test_client):
    t = get_local_timezone().localize(datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            'description': 'testing',
            'event_time': t,
            'details': { 'hello': 'world' },
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            'queue': 'default',
            'instructions': 'Test instructions.',
            'extensions': { KEY_PLAYBOOK_URL: "http://playbook" },
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    result = result.get_json()
    assert result

    assert 'result' in result
    result = result['result']
    assert result['uuid']
    #self.assertIsNotNone(result['id'])

    uuid = result['uuid']
    #_id = result['id']

    result = test_client.get(url_for('analysis.get_analysis', uuid=uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    result = result.get_json()
    assert result
    assert 'result' in result
    result = result['result']

    assert result['analysis_mode'] == 'analysis'
    assert result['tool'] == 'unittest'
    assert result['tool_instance'] == 'unittest_instance'
    assert result['type'] == 'unittest'
    assert result['description'] == 'testing'
    assert result['queue'] == 'default'
    assert result['instructions'] == 'Test instructions.'
    assert result['extensions'] == { KEY_PLAYBOOK_URL: "http://playbook" }
    assert result['event_time'] == '2017-11-11T07:36:01.000001+0000'
    assert result['tags'][0] == 'alert_tag_1'
    assert result['tags'][1] == 'alert_tag_2'
    assert len(result['observable_store']) == 3

    file_uuid = None

    for o_uuid in result['observable_store']:
        observable = result['observable_store'][o_uuid]
        if observable['type'] == F_IPV4:
            assert observable['type'] == F_IPV4
            assert observable['value'] == '1.2.3.4'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'
            assert observable['tags'][0] == 'tag_1'
            assert observable['tags'][1] == 'tag_2'
            assert observable['directives'][0] == DIRECTIVE_NO_SCAN
            assert observable['limited_analysis'][0] == 'basic_test'
        elif observable['type'] == F_USER:
            assert observable['type'] == F_USER
            assert observable['value'] == 'test_user'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'
        elif observable['type'] == F_FILE:
            assert observable['type'] == F_FILE
            assert observable['file_path'] == 'sample.dat'
            assert observable['time'] is None
            assert observable['uuid'] is not None
            file_uuid = observable['uuid']

    # we should see a single workload entry
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, uuid, node_id, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
        row = cursor.fetchone()

    assert row
    assert row[0]
    assert row[1] == uuid
    assert row[2] == get_global_runtime_settings().saq_node_id
    assert row[3] == 'analysis'

    result = test_client.get(url_for('analysis.get_details', uuid=uuid, name=result['file_path']), headers = { 'x-ace-auth': get_config().api.api_key })
    result = result.get_json()
    assert result
    result = result['result']
    assert 'hello' in result
    assert result['hello'] == 'world'

    result = test_client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name=file_uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200
    assert result.data == b'Hello, world!'

    result = test_client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name='sample.dat'), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200
    assert result.data == b'Hello, world!'

    result = test_client.get(url_for('analysis.get_status', uuid=uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200
    result = result.get_json()
    assert result
    result = result['result']
    assert 'workload' in result
    assert 'delayed_analysis' in result
    assert 'locks' in result
    assert result['delayed_analysis'] == []
    assert result['locks'] is None
    assert isinstance(result['workload']['id'], int)
    assert result['workload']['uuid'] == uuid
    assert result['workload']['node_id'] == get_global_runtime_settings().saq_node_id
    assert result['workload']['analysis_mode'] == 'analysis'
    assert isinstance(parse_event_time(result['workload']['insert_date']), datetime)

    result = test_client.get(url_for('analysis.get_submission', uuid=uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code, 200
    result = result.get_json()
    assert result
    result = result['result']

    assert result['analysis_mode'] == 'analysis'
    assert result['tool'] == 'unittest'
    assert result['tool_instance'] == 'unittest_instance'
    assert result['type'] == 'unittest'
    assert result['description'] == 'testing'
    assert result['queue'] == 'default'
    assert result['instructions'] == 'Test instructions.'
    assert result['event_time'] == '2017-11-11T07:36:01.000001+0000'
    assert 'alert_tag_1' in result['tags']
    assert 'alert_tag_2' in result['tags']
    assert len(result['observables']) == 2

    file_uuid = None

    for observable in result['observables']:
        if observable['type'] == F_IPV4:
            assert observable['type'] == F_IPV4
            assert observable['value'] == '1.2.3.4'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'
            assert observable['tags'][0] == 'tag_1'
            assert observable['tags'][1] == 'tag_2'
            assert observable['directives'][0] == DIRECTIVE_NO_SCAN
            assert observable['limited_analysis'][0] == 'basic_test'
        elif observable['type'] == F_USER:
            assert observable['type'] == F_USER
            assert observable['value'] == 'test_user'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'

    assert result["files"][0].endswith("files/sample.dat")
    
    
@pytest.mark.integration
def test_api_analysis_submit_queue(test_client):
    t = get_local_timezone().localize(datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            'description': 'testing',
            'event_time': t,
            'details': { 'hello': 'world' },
            'queue': 'internal',
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    result = result.get_json()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']
    result = test_client.get(url_for('analysis.get_analysis', uuid=uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    result = result.get_json()
    assert result
    assert 'result' in result
    result = result['result']

    assert result['analysis_mode'] == 'analysis'
    assert result['tool'] == 'unittest'
    assert result['tool_instance'] == 'unittest_instance'
    assert result['type'] == 'unittest'
    assert result['description'] == 'testing'
    assert result['queue'] == 'internal'
    assert result['event_time'] == '2017-11-11T07:36:01.000001+0000'
    assert result['tags'][0] == 'alert_tag_1'
    assert result['tags'][1] == 'alert_tag_2'
    assert len(result['observable_store']) == 3

    file_uuid = None

    for o_uuid in result['observable_store']:
        observable = result['observable_store'][o_uuid]
        if observable['type'] == F_IPV4:
            assert observable['type'] == F_IPV4
            assert observable['value'] == '1.2.3.4'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'
            assert observable['tags'][0] == 'tag_1'
            assert observable['tags'][1] == 'tag_2'
            assert observable['directives'][0] == DIRECTIVE_NO_SCAN
            assert observable['limited_analysis'][0] == 'basic_test'
        elif observable['type'] == F_USER:
            assert observable['type'] == F_USER
            assert observable['value'] == 'test_user'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'
        elif observable['type'] == F_FILE:
            assert observable['type'] == F_FILE
            assert observable['file_path'] == 'sample.dat'
            assert observable['time'] is None
            assert observable['uuid']
            file_uuid = observable['uuid']

    # we should see a single workload entry
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, uuid, node_id, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
        row = cursor.fetchone()

    assert row
    assert row[0]
    assert row[1] == uuid
    assert row[2] == get_global_runtime_settings().saq_node_id
    assert row[3] == 'analysis'

    result = test_client.get(url_for('analysis.get_details', uuid=uuid, name=result['file_path']), headers = { 'x-ace-auth': get_config().api.api_key })
    result = result.get_json()
    assert result
    result = result['result']
    assert 'hello' in result
    assert result['hello'] == 'world'

    result = test_client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name=file_uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200
    assert result.data == b'Hello, world!'

    result = test_client.get(url_for('analysis.get_file', uuid=uuid, file_uuid_or_name='sample.dat'), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200
    assert result.data == b'Hello, world!'

    result = test_client.get(url_for('analysis.get_status', uuid=uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200
    result = result.get_json()
    assert result
    result = result['result']
    assert 'workload' in result
    assert 'delayed_analysis' in result
    assert 'locks' in result
    assert result['delayed_analysis'] == []
    assert result['locks'] is None
    assert isinstance(result['workload']['id'], int)
    assert result['workload']['uuid'] == uuid
    assert result['workload']['node_id'] == get_global_runtime_settings().saq_node_id
    assert result['workload']['analysis_mode'] == 'analysis'
    assert isinstance(parse_event_time(result['workload']['insert_date']), datetime)

    result = test_client.get(url_for('analysis.get_submission', uuid=uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200
    result = result.get_json()
    assert result
    result = result['result']

    assert result['analysis_mode'] == 'analysis'
    assert result['tool'] == 'unittest'
    assert result['tool_instance'] == 'unittest_instance'
    assert result['type'] == 'unittest'
    assert result['description'] == 'testing'
    assert result['event_time'] == '2017-11-11T07:36:01.000001+0000'
    assert 'alert_tag_1' in result['tags']
    assert 'alert_tag_2' in result['tags']
    assert len(result['observables']) == 2

    file_uuid = None

    for observable in result['observables']:
        if observable['type'] == F_IPV4:
            assert observable['type'] == F_IPV4
            assert observable['value'] == '1.2.3.4'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'
            assert observable['tags'][0] == 'tag_1'
            assert observable['tags'][1] == 'tag_2'
            assert observable['directives'][0] == DIRECTIVE_NO_SCAN
            assert observable['limited_analysis'][0] == 'basic_test'
        elif observable['type'] == F_USER:
            assert observable['type'] == F_USER
            assert observable['value'] == 'test_user'
            assert observable['time'] == '2017-11-11T07:36:01.000001+0000'

    assert result["files"][0].endswith("files/sample.dat")

@pytest.mark.integration
def test_api_analysis_submit_invalid(test_client):
    result = test_client.post(url_for('analysis.submit'), data={}, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 400
    assert result.data.decode() == 'missing analysis field (see documentation)'

    t = get_local_timezone().localize(datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            'description': 'testing',
            'event_time': t,
            'details': { 'hello': 'world' },
            'company_name': 'invalid_company_name',
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    assert result.status_code == 400
    assert result.data.decode() == 'wrong company invalid_company_name (are you sending to the correct system?)'

    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            #'description': 'testing', <-- missing description
            'event_time': t,
            'details': { 'hello': 'world' },
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    assert result.status_code == 400
    assert result.data.decode() == 'missing description field in submission'

    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            'description': 'testing', 
            'event_time': '20189-13-143', # <-- invalid event time
            'details': { 'hello': 'world' },
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    assert result.status_code == 400
    assert 'invalid event time format' in result.data.decode()
    # there should only be one entry in the node directory, but that should be empty

    def _get_alert_dir_count():
        """Returns a tuple of subdir_count, alert_count where subdir_count is the count of sub directories in the node directory,
            and alert_count is the count of sub directories in the subdirs (the alert directories)."""
        subdirs = os.listdir(os.path.join(get_data_dir(), get_global_runtime_settings().saq_node))
        count = 0
        for subdir in subdirs:
            count += len(os.listdir(os.path.join(get_data_dir(), get_global_runtime_settings().saq_node, subdir)))

        return len(subdirs), count

    subdir_count, alertdir_count = _get_alert_dir_count()
    assert alertdir_count == 0

    with pytest.raises(KeyError):
        result = test_client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                                # \/ missing value
                    { 'type': F_IPV4, 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    #assert result.status_code == 400
    #assert result.data.decode() == 'an observable is missing the value field'
    # there should be nothing in the data directory (it should have been removed)
    #subdir_count, alertdir_count = _get_alert_dir_count()
    #assert alertdir_count == 0

    with pytest.raises(KeyError):
        result = test_client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    # missing type
                    { 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    #assert result.status_code == 400
    #assert result.data.decode(), 'an observable is missing the type field'
    # there should be nothing in the data directory (it should have been removed)
    #subdir_count, alertdir_count = _get_alert_dir_count()
    #assert alertdir_count == 0

    with pytest.raises(ValueError):
        result = test_client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'analysis',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'unittest',
                'description': 'testing',
                'event_time': t,
                'details': { 'hello': 'world' },
                'observables': [
                    { 'type': F_IPV4, 'value': '1.2.3.4', 'time': 'INVALID_TIME', 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                    { 'type': F_USER, 'value': 'test_user', 'time': t },
                ],
                'tags': [ 'alert_tag_1', 'alert_tag_2' ],
            }, cls=_JSONEncoder),
            'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
        }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    #assert result.status_code == 400
    #assert 'an observable has an invalid time format' in result.data.decode()
    # there should be nothing in the data directory (it should have been removed)
    #subdir_count, alertdir_count = _get_alert_dir_count()
    #assert alertdir_count == 0

@pytest.mark.integration
def test_api_analysis_invalid_status(test_client):
    result = test_client.get(url_for('analysis.get_status', uuid='invalid'), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 400

    test_uuid = str(uuid.uuid4())
    result = test_client.get(url_for('analysis.get_status', uuid=test_uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 400
    assert result.data.decode() == 'invalid uuid {}'.format(test_uuid)

@pytest.mark.integration
def test_api_analysis_submission_tuning(test_client):

    tuning_rule_dir = os.path.join(get_data_dir(), 'tuning_rules')
    if os.path.isdir(tuning_rule_dir):
        shutil.rmtree(tuning_rule_dir)

    os.mkdir(tuning_rule_dir)
    get_config().collection.tuning_dirs = [tuning_rule_dir]
    get_config().collection.tuning_update_frequency = '00:00:00'

    with open(os.path.join(tuning_rule_dir, 'filter.yar'), 'w') as fp:
        fp.write("""
rule test_filter {
    meta:
        targets = "submission"
    strings:
        $ = "description = testing"
    condition:
        all of them
}
""")

    t = get_local_timezone().localize(datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            'description': 'testing',
            'event_time': t,
            'details': { 'hello': 'world' },
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    result = result.get_json()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    assert 'tuning_matches' in result

    result = test_client.get(url_for('analysis.get_analysis', uuid=result['uuid']), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 400

    # remove the tuning rule
    os.remove(os.path.join(tuning_rule_dir, 'filter.yar'))

    t = get_local_timezone().localize(datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            'description': 'testing',
            'event_time': t,
            'details': { 'hello': 'world' },
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    result = result.get_json()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    assert 'tuning_matches' not in result

    result = test_client.get(url_for('analysis.get_analysis', uuid=result['uuid']), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200

    # test tuning by file
    with open(os.path.join(tuning_rule_dir, 'file_filter.yar'), 'w') as fp:
        fp.write("""
rule test_files {
    meta:
        targets = "files"
    strings:
        $ = "Hello, world!"
    condition:
        all of them
}
""")

    t = get_local_timezone().localize(datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
    result = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': 'analysis',
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': 'unittest',
            'description': 'testing',
            'event_time': t,
            'details': { 'hello': 'world' },
            'observables': [
                { 'type': F_IPV4, 'value': '1.2.3.4', 'time': t, 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ DIRECTIVE_NO_SCAN ], 'limited_analysis': ['basic_test'] },
                { 'type': F_USER, 'value': 'test_user', 'time': t },
            ],
            'tags': [ 'alert_tag_1', 'alert_tag_2' ],
        }, cls=_JSONEncoder),
        'file': (io.BytesIO(b'Hello, world!'), 'sample.dat'),
    }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    result = result.get_json()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    assert 'tuning_matches' in result

    result = test_client.get(url_for('analysis.get_analysis', uuid=result['uuid']), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 400