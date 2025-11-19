import io
import os
import pickle
import shutil
import tempfile
import uuid
import pytest
import pytz
import requests

from datetime import datetime

import ace_api
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, DIRECTIVE_NO_SCAN, F_FILE, F_IPV4, G_API_PREFIX, G_TEMP_DIR
from saq.database.pool import get_db_connection
from saq.database.util.locking import acquire_lock
from saq.environment import g
from saq.observables.file import FileObservable
from saq.util.time import local_time, parse_event_time
from saq.util.uuid import get_storage_dir, validate_uuid
from tests.saq.helpers import create_root_analysis, log_count, start_api_server, stop_api_server

@pytest.fixture(autouse=True, scope="function")
def api_server():
    ace_api.set_default_api_key(get_config()["api"]["api_key"])
    api_server_process = start_api_server(
        remote_host=g(G_API_PREFIX),
        ssl_verification=get_config()['SSL']['ca_chain_path'],

    )

    yield api_server_process

    stop_api_server(api_server_process)

@pytest.mark.integration
def test_invalid_auth(mock_api_call):
    ace_api.set_default_api_key("invalid")
    with pytest.raises(requests.exceptions.HTTPError):
        result = ace_api.ping()

@pytest.mark.integration
def test_ping(mock_api_call):
    result = ace_api.ping()
    assert result
    assert 'result' in result
    assert result['result'] == 'pong'

@pytest.mark.integration
def test_get_supported_api_version(mock_api_call):
    result = ace_api.get_supported_api_version()
    assert result
    assert 'result' in result
    assert result['result'] == 1

@pytest.mark.integration
def test_get_valid_companies(mock_api_call):
    result = ace_api.get_valid_companies()
    assert result
    assert 'result' in result
    assert isinstance(result['result'], list)

    lookup = {}
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, name FROM company")
        for _id, _name in cursor:
            lookup[_id] = _name

    assert len(lookup) == len(result['result'])
    for _ in result['result']:
        assert _['id'] in lookup and lookup[_['id']] == _['name']

    result = ace_api.get_valid_companies()
    assert result
    assert 'result' in result
    assert isinstance(result['result'], list)

@pytest.mark.skip(reason="Need to fix")
@pytest.mark.integration
def test_get_valid_observables():
    from saq.constants import VALID_OBSERVABLE_TYPES, OBSERVABLE_DESCRIPTIONS, DEPRECATED_OBSERVABLES
    result = ace_api.get_valid_observables()
    assert result
    assert 'result' in result
    assert isinstance(result['result'], list)

    for _ in result['result']:
        assert _['name'] in VALID_OBSERVABLE_TYPES
        assert OBSERVABLE_DESCRIPTIONS[_['name']] == _['description']

    active_observables = set(VALID_OBSERVABLE_TYPES) - set(DEPRECATED_OBSERVABLES)
    assert len(active_observables) == len(result['result'])

@pytest.mark.integration
def test_get_valid_directives(mock_api_call):
    from saq.constants import VALID_DIRECTIVES, DIRECTIVE_DESCRIPTIONS
    result = ace_api.get_valid_directives()
    assert result
    assert 'result' in result
    assert isinstance(result['result'], list)

    for _ in result['result']:
        assert _['name'] in VALID_DIRECTIVES
        assert DIRECTIVE_DESCRIPTIONS[_['name']] == _['description']

def _get_submit_time():
    return datetime(2017, 11, 11, hour=7, minute=36, second=1)

def _get_localized_submit_time():
    return ace_api.LOCAL_TIMEZONE.localize(_get_submit_time()).astimezone(pytz.timezone('UTC'))

def _submit(analysis_mode=None,
            tool=None,
            tool_instance=None,
            type=None,
            description=None,
            details=None,
            event_time=None,
            observables=None,
            tags=None):

    temp_path = os.path.join(g(G_TEMP_DIR), 'submit_test.dat')
    temp_data = os.urandom(1024)

    with open(temp_path, 'wb') as fp:
        fp.write(temp_data)

    try:
        with open(temp_path, 'rb') as fp:
            return ace_api.submit(
                analysis_mode='test_empty' if analysis_mode is None else analysis_mode, 
                tool='unittest_tool' if tool is None else tool,
                tool_instance='unittest_tool_instance' if tool_instance is None else tool_instance,
                type='unittest_type' if type is None else type,
                description='testing' if description is None else description,
                details={'hello': 'world'} if details is None else details,
                event_time=_get_submit_time() if event_time is None else event_time,
                observables=[
                        { 'type': 'ipv4', 'value': '1.2.3.4', 'time': _get_submit_time(), 'tags': [ 'tag_1', 'tag_2' ], 'directives': [ 'no_scan' ], 'limited_analysis': ['basic_test'] },
                        { 'type': 'user', 'value': 'test_user', 'time': _get_submit_time() },
                ] if observables is None else observables,
                tags=[ 'alert_tag_1', 'alert_tag_2' ] if tags is None else tags,
                files=[('sample.dat', io.BytesIO(b'Hello, world!')),
                        ('submit_test.dat', fp)])
    finally:
        os.remove(temp_path)

@pytest.mark.integration
def test_submit(mock_api_call):
    result = _submit()
    assert result

    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    # make sure this actually uploaded
    root = RootAnalysis(storage_dir=get_storage_dir(uuid))
    root.load()

    assert root.analysis_mode == 'test_empty'
    assert root.tool == 'unittest_tool'
    assert root.tool_instance == 'unittest_tool_instance'
    assert root.alert_type == 'unittest_type'
    assert root.description == 'testing'
    assert root.details == {'hello': 'world'}
    assert root.event_time == _get_localized_submit_time()
    assert root.tags[0].name == 'alert_tag_1'
    assert root.tags[1].name == 'alert_tag_2'
    # NOTE that this is 4 instead of 2 since adding a file adds a F_FILE observable type
    assert len(root.all_observables) == 4

    observable = root.find_observable(lambda o: o.type == 'ipv4')
    assert observable
    assert observable.value == '1.2.3.4'
    assert len(observable.tags) == 2
    assert observable.has_directive('no_scan')
    assert 'basic_test' in observable.limited_analysis

    observable = root.find_observable(lambda o: o.type == 'file' and o.file_name == 'sample.dat')
    assert observable

    with open(observable.full_path, 'rb') as fp:
        assert fp.read() == b'Hello, world!'

    observable = root.find_observable(lambda o: o.type == 'file' and o.file_name == 'submit_test.dat')
    assert isinstance(observable, FileObservable)
    assert observable.size == 1024

    # we should see a single workload entry
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, uuid, node_id, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
        row = cursor.fetchone()

    assert row
    assert row[0]
    assert row[1] == uuid
    assert row[2]
    assert row[3] == 'test_empty'

@pytest.mark.integration
def test_resubmit(mock_api_call):
    # submit something so we have something to resubmit
    result = _submit(analysis_mode=ANALYSIS_MODE_CORRELATION)
    assert result

    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    # make sure this actually uploaded
    root = RootAnalysis(storage_dir=get_storage_dir(uuid))
    root.load()

    assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
    assert root.tool == 'unittest_tool'
    assert root.tool_instance == 'unittest_tool_instance'
    assert root.alert_type == 'unittest_type'
    assert root.description == 'testing'
    assert root.details == {'hello': 'world'}
    assert root.event_time == _get_localized_submit_time()
    assert root.tags[0].name == 'alert_tag_1'
    assert root.tags[1].name == 'alert_tag_2'
    # NOTE that this is 4 instead of 2 since adding a file adds a F_FILE observable type
    assert len(root.all_observables) == 4

    observable = root.find_observable(lambda o: o.type == 'ipv4')
    observable
    assert observable.value == '1.2.3.4'
    assert len(observable.tags) == 2
    assert observable.has_directive('no_scan')
    assert 'basic_test' in observable.limited_analysis

    observable = root.find_observable(lambda o: o.type == 'file' and o.file_path == 'sample.dat')
    assert observable

    with open(observable.full_path, 'rb') as fp:
        assert fp.read() == b'Hello, world!'

    observable = root.find_observable(lambda o: o.type == 'file' and o.file_path == 'submit_test.dat')
    assert isinstance(observable, FileObservable)
    assert observable.size == 1024

    # we should see a single workload entry
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, uuid, node_id, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
        row = cursor.fetchone()

    assert row
    assert row[0]
    assert row[1] == uuid
    assert row[2]
    assert row[3] == ANALYSIS_MODE_CORRELATION

    # now resubmit the alert
    result = ace_api.resubmit_alert(uuid)
    assert not 'error' in result

@pytest.mark.integration
def test_submit_with_utc_timezone(mock_api_call):
    # make sure we can submit with a UTC timezone already set
    result = _submit(event_time=_get_localized_submit_time())
    assert result

    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    root = RootAnalysis(storage_dir=get_storage_dir(uuid))
    root.load()

    assert root.event_time == _get_localized_submit_time()

@pytest.mark.integration
def test_submit_with_other_timezone(mock_api_call):
    # make sure we can submit with another timezone already set
    result = _submit(event_time=_get_localized_submit_time().astimezone(pytz.timezone('US/Eastern')))
    assert result

    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    root = RootAnalysis(storage_dir=get_storage_dir(uuid))
    root.load()

    assert root.event_time == _get_localized_submit_time()

@pytest.mark.integration
def test_get_analysis(mock_api_call):

    result = _submit()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    result = ace_api.get_analysis(uuid)
    assert result
    assert 'result' in result
    result = result['result']

    assert result['analysis_mode'] == 'test_empty'
    assert result['tool'] == 'unittest_tool'
    assert result['tool_instance'] == 'unittest_tool_instance'
    assert result['type'] == 'unittest_type'
    assert result['description'] == 'testing'
    assert result['event_time'] == '2017-11-11T07:36:01.000000+0000'
    assert result['tags'][0] == 'alert_tag_1'
    assert result['tags'][1] == 'alert_tag_2'
    assert len(result['observable_store']) == 4

    # the details should be a file_path reference
    assert isinstance(result['file_path'], str)
    assert result['file_path'].startswith('RootAnalysis_')

@pytest.mark.integration
def test_get_analysis_details(mock_api_call):
    
    result = _submit()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    result = ace_api.get_analysis(uuid)
    assert result
    assert 'result' in result
    result = result['result']

    details_result = ace_api.get_analysis_details(uuid, result['file_path'])
    assert details_result
    details_result = details_result['result']
    assert 'hello' in details_result
    assert details_result['hello'], 'world'

@pytest.mark.integration
def test_get_analysis_file(mock_api_call):

    result = _submit()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    result = ace_api.get_analysis(uuid)
    assert result
    assert 'result' in result
    result = result['result']

    # first test getting a file by uuid
    file_uuid = None
    for o_uuid in result['observables']:
        o = result['observable_store'][o_uuid]
        if o['type'] == 'file' and o['file_path'] == 'sample.dat':
            file_uuid = o_uuid
            break

    assert file_uuid

    output_path = os.path.join(g(G_TEMP_DIR), 'get_file_test.dat')
    assert ace_api.get_analysis_file(uuid, file_uuid, output_file=output_path)
    with open(output_path, 'rb') as fp:
        assert fp.read() == b'Hello, world!'

    # same thing but with passing a file pointer
    with open(output_path, 'wb') as fp:
        assert ace_api.get_analysis_file(uuid, file_uuid, output_fp=fp)

    # now test by using the file name
    assert ace_api.get_analysis_file(uuid, 'sample.dat', output_file=output_path)
    with open(output_path, 'rb') as fp:
        assert fp.read() == b'Hello, world!'

@pytest.mark.integration
def test_get_analysis_status(mock_api_call):

    result = _submit()
    assert result
    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    result = ace_api.get_analysis_status(uuid)
    assert result
    result = result['result']
    assert 'workload' in result
    assert 'delayed_analysis' in result
    assert 'locks' in result
    assert 'alert' in result
    assert result['alert'] is None
    assert result['delayed_analysis'] == []
    assert result['locks'] is None
    assert isinstance(result['workload']['id'], int)
    assert result['workload']['uuid'] == uuid
    assert result['workload']['node_id']
    assert result['workload']['analysis_mode'] == 'test_empty'
    assert isinstance(parse_event_time(result['workload']['insert_date']), datetime)

@pytest.mark.integration
def test_download(mock_api_call):
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    root.save()

    temp_dir = tempfile.mkdtemp(dir=g(G_TEMP_DIR))
    try:
        result = ace_api.download(root.uuid, temp_dir)
        assert os.path.join(temp_dir, 'data.json')
        root = RootAnalysis(storage_dir=temp_dir)
        root.load()
        assert root.details == { 'hello': 'world' }
    finally:
        shutil.rmtree(temp_dir)

@pytest.mark.integration
def test_upload(mock_api_call):
    root = create_root_analysis(uuid=str(uuid.uuid4()), storage_dir=os.path.join(g(G_TEMP_DIR), 'unittest'))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    root.save()

    result = ace_api.upload(root.uuid, root.storage_dir)
    assert result['result']

    # uploads go straight into saq.DATA_DIR
    root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
    root.load()

    assert root.details == { 'hello': 'world' }

@pytest.mark.integration
def test_clear(mock_api_call):
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    root.save()
    assert os.path.exists(root.storage_dir)

    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(root.uuid, lock_uuid)

    assert ace_api.clear(root.uuid, lock_uuid)

@pytest.mark.integration
def test_clear_invalid_lock_uuid(mock_api_call):
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    root.save()
    assert os.path.exists(root.storage_dir)

    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(root.uuid, lock_uuid)

    lock_uuid = str(uuid.uuid4())
    with pytest.raises(Exception):
        assert not ace_api.clear(root.uuid, lock_uuid)

    assert os.path.exists(root.storage_dir)

@pytest.mark.integration
def test_legacy_submit(mock_api_call):
    
    alert = ace_api.Alert(description='Test Alert')
    alert.add_observable_by_spec(F_IPV4, '1.2.3.4', local_time(), directives=[DIRECTIVE_NO_SCAN])
    alert.add_tag('test')
    temp_path = os.path.join(g(G_TEMP_DIR), 'test.txt')
    with open(temp_path, 'w') as fp:
        fp.write('test')

    alert.add_attachment_link(temp_path, 'dest/test.txt')
    alert.submit(f'https://{g(G_API_PREFIX)}', ssl_verification=get_config()['SSL']['ca_chain_path'])
    assert validate_uuid(alert.uuid)

    root = RootAnalysis(storage_dir=get_storage_dir(alert.uuid))
    root.load()

    assert root.description == 'Test Alert'
    ipv4_observable = root.find_observable(lambda o: o.type == F_IPV4)
    assert ipv4_observable
    assert ipv4_observable.value == '1.2.3.4'
    assert ipv4_observable.has_directive(DIRECTIVE_NO_SCAN)
    
    file_observable = root.find_observable(lambda o: o.type == F_FILE)
    assert file_observable
    assert file_observable.file_path == 'dest/test.txt'
    with open(file_observable.full_path, 'r') as fp:
        assert fp.read() == 'test'

@pytest.mark.integration
def test_legacy_import(mock_api_call):
    from ace_api import Alert

@pytest.mark.skip(reason="skipping tests with api_server")
@pytest.mark.system
def test_legacy_failed_submit(api_server, tmpdir):

    fail_dir = tmpdir / "failed"
    fail_dir.mkdir()
    fail_dir = str(fail_dir)

    stop_api_server(api_server)

    alert = ace_api.Alert(description='Test Alert')
    alert.add_observable_by_spec(F_IPV4, '1.2.3.4', local_time(), directives=[DIRECTIVE_NO_SCAN])
    alert.add_tag('test')
    temp_path = os.path.join(g(G_TEMP_DIR), 'test.txt')
    with open(temp_path, 'w') as fp:
        fp.write('test')

    alert.add_attachment_link(temp_path, 'dest/test.txt')
    with pytest.raises(Exception):
        alert.submit(f'https://{g(G_API_PREFIX)}', ssl_verification=get_config()['SSL']['ca_chain_path'], fail_dir=fail_dir)

    assert log_count('unable to submit ') == 1

    # the .saq_alerts directory should have a single subdirectory
    dir_list = os.listdir(fail_dir)
    assert len(dir_list) == 1
    
    # load the alert
    target_path = os.path.join(fail_dir, dir_list[0], 'alert')
    with open(target_path, 'rb') as fp:
        new_alert = pickle.load(fp)

    assert new_alert.submit_kwargs == alert.submit_kwargs

@pytest.mark.skip(reason="Forget the legacy submit")
@pytest.mark.system
def test_failed_submit(api_server, tmpdir):

    fail_dir = tmpdir / "failed"
    fail_dir.mkdir()
    fail_dir = str(fail_dir)

    stop_api_server(api_server)

    analysis = ace_api.Analysis(description='Test Analysis submit')
    analysis.add_observable_by_spec(F_IPV4, '1.2.3.4', local_time(), directives=[DIRECTIVE_NO_SCAN])
    analysis.add_tag('test')
    analysis.add_user('test_user')
    temp_path = os.path.join(g(G_TEMP_DIR), 'test.txt')
    with open(temp_path, 'w') as fp:
        fp.write('test')

    analysis.add_file(temp_path, relative_storage_path='dest/test.txt')
    with pytest.raises(Exception):
        analysis.submit(f'https://{g(G_API_PREFIX)}', ssl_verification=get_config()['SSL']['ca_chain_path'], fail_dir=fail_dir)

    assert log_count('unable to submit ') == 1

    # the .saq_alerts directory should have a single subdirectory
    dir_list = os.listdir(fail_dir)
    assert len(dir_list) == 1

    # load the analysis object
    target_path = os.path.join(fail_dir, dir_list[0], 'alert')
    with open(target_path, 'rb') as fp:
        new_analysis = pickle.load(fp)

    assert new_analysis.submit_kwargs == analysis.submit_kwargs

@pytest.mark.skip(reason="skipping tests with api_server")
def test_submit_failed_alerts(api_server, tmpdir):

    fail_dir = tmpdir / "failed"
    fail_dir.mkdir()
    fail_dir = str(fail_dir)

    stop_api_server(api_server)

    alert = ace_api.Alert(description='Test Alert')
    alert.add_observable_by_spec(F_IPV4, '1.2.3.4', local_time(), directives=[DIRECTIVE_NO_SCAN])
    alert.add_tag('test')
    temp_path = os.path.join(g(G_TEMP_DIR), 'test.txt')
    with open(temp_path, 'w') as fp:
        fp.write('test')

    alert.add_attachment_link(temp_path, 'dest/test.txt')
    with pytest.raises(Exception):
        uuid = alert.submit(f'https://{g(G_API_PREFIX)}', ssl_verification=get_config()['SSL']['ca_chain_path'], fail_dir=fail_dir)

    assert log_count('unable to submit ') == 1

    # the .saq_alerts directory should have a single subdirectory
    dir_list = os.listdir(fail_dir)
    assert len(dir_list) == 1
    
    # load the alert
    target_path = os.path.join(fail_dir, dir_list[0], 'alert')
    with open(target_path, 'rb') as fp:
        new_alert = pickle.load(fp)

    assert new_alert.submit_kwargs == alert.submit_kwargs

    # try to submit it using submit_failed_alerts
    api_server = start_api_server()
    try:
        ace_api.submit_failed_alerts(delete_on_success=True, fail_dir=fail_dir)
        
        # this directory should be cleared out
        dir_list = os.listdir(fail_dir)
        assert len(dir_list) == 0

    finally:
        stop_api_server(api_server)

@pytest.mark.skip(reason="skipping tests with api_server")
@pytest.mark.system
def test_submit_failed_analysis(api_server, tmpdir):

    fail_dir = tmpdir / "failed"
    fail_dir.mkdir()
    fail_dir = str(fail_dir)

    stop_api_server(api_server)

    analysis = ace_api.Analysis(description='Test Analysis')
    analysis.add_observable_by_spec(F_IPV4, '1.2.3.4', local_time(), directives=[DIRECTIVE_NO_SCAN])
    analysis.add_tag('test')
    temp_path = os.path.join(g(G_TEMP_DIR), 'test.txt')
    with open(temp_path, 'w') as fp:
        fp.write('test')

    analysis.add_file(temp_path, relative_storage_path='dest/test.txt')
    with pytest.raises(Exception):
        uuid = analysis.submit(f'https://{g(G_API_PREFIX)}', ssl_verification=get_config()['SSL']['ca_chain_path'], fail_dir=fail_dir)

    assert log_count('unable to submit ') == 1

    # the .saq_alerts directory should have a single subdirectory
    dir_list = os.listdir(fail_dir)
    assert len(dir_list) == 1

    # load the alert
    target_path = os.path.join(fail_dir, dir_list[0], 'alert')
    with open(target_path, 'rb') as fp:
        new_analysis = pickle.load(fp)

    assert new_analysis.submit_kwargs == analysis.submit_kwargs

    # did we actually write data to the file?
    data_test = None
    with open(os.path.join(fail_dir, new_analysis.uuid, 'dest/test.txt'), 'r') as fp:
        data_test = fp.read()
 
    assert data_test == 'test'

    # try to submit it using submit_failed_alerts
    api_server = start_api_server()
    try:
        ace_api.submit_failed_alerts(delete_on_success=True, fail_dir=fail_dir)

        # this directory should be cleared out
        dir_list = os.listdir(fail_dir)
        assert len(dir_list) == 0
    finally:
        stop_api_server(api_server)

@pytest.mark.integration
def test_analysis_file_handling(mock_api_call, tmpdir):

    normal_file_path = tmpdir / "normal.txt"
    normal_file_path.write_text("test", encoding="utf8")
    normal_file_path = str(normal_file_path)

    fp_file_path = tmpdir / "fp.txt"
    fp_file_path.write_text("test", encoding="utf8")
    fp_file_path = str(fp_file_path)

    subdir_file_path = tmpdir / "subdir.txt"
    subdir_file_path.write_text("test", encoding="utf8")
    subdir_file_path = str(subdir_file_path)

    analysis = ace_api.Analysis(description='Test Analysis')
    # add a normal file
    analysis.add_file(normal_file_path)
    # add a normal file, passing in the file pointer
    fp = open(fp_file_path, 'rb')
    analysis.add_file(fp_file_path, fp)
    # add a normal file but tell it to go into a subdirectory
    analysis.add_file(subdir_file_path, relative_storage_path='subdir/subdir.txt')
    # add a file passing the contents as a string
    analysis.add_file('str.txt', 'This is a string.')
    # add a file passing the contents as a bytes
    analysis.add_file('bytes.txt', b'This is a bytes.')

    result = analysis.submit()

    # make sure it got our files
    io_buffer = io.BytesIO()
    ace_api.get_analysis_file(result.uuid, 'normal.txt', output_fp=io_buffer)
    with open(normal_file_path, 'rb') as fp:
        assert fp.read() == io_buffer.getvalue()

    io_buffer = io.BytesIO()
    ace_api.get_analysis_file(result.uuid, 'fp.txt', output_fp=io_buffer)
    with open(fp_file_path, 'rb') as fp:
        assert fp.read() == io_buffer.getvalue()

    io_buffer = io.BytesIO()
    ace_api.get_analysis_file(result.uuid, 'str.txt', output_fp=io_buffer)
    assert b'This is a string.' == io_buffer.getvalue()

    io_buffer = io.BytesIO()
    ace_api.get_analysis_file(result.uuid, 'bytes.txt', output_fp=io_buffer)
    assert b'This is a bytes.' == io_buffer.getvalue()

@pytest.mark.integration
def test_get_open_events(mock_api_call):
    result = ace_api.get_open_events()
    assert result == []

@pytest.mark.integration
def test_update_event_status(mock_api_call):
    # Create an event
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO `event_type` (`value`) VALUES ('phish');""")
        cursor.execute("""INSERT INTO `event_status` (`value`) VALUES ('OPEN');""")
        cursor.execute("""INSERT INTO `event_vector` (`value`) VALUES ('corporate email');""")
        cursor.execute("""INSERT INTO `event_prevention_tool` (`value`) VALUES ('response team');""")
        cursor.execute("""INSERT INTO `event_remediation` (`value`) VALUES ('not remediated');""")
        cursor.execute("""INSERT INTO `event_risk_level` (`value`) VALUES ('1');""")
        db.commit()

        cursor.execute("""SELECT id FROM event_type ORDER BY id LIMIT 1""")
        event_type_id = cursor.fetchone()[0]
        cursor.execute("""SELECT id FROM event_status ORDER BY id LIMIT 1""")
        event_status_id = cursor.fetchone()[0]
        cursor.execute("""SELECT id FROM event_vector ORDER BY id LIMIT 1""")
        event_vector_id = cursor.fetchone()[0]
        cursor.execute("""SELECT id FROM event_prevention_tool ORDER BY id LIMIT 1""")
        event_prevention_tool_id = cursor.fetchone()[0]
        cursor.execute("""SELECT id FROM event_remediation ORDER BY id LIMIT 1""")
        event_remediation_id = cursor.fetchone()[0]
        cursor.execute("""SELECT id FROM event_risk_level ORDER BY id LIMIT 1""")
        event_risk_level_id = cursor.fetchone()[0]
        cursor.execute(f"""
                        INSERT INTO `events`
                        (`creation_date`,
                        `name`,
                        `type_id`,
                        `vector_id`,
                        `prevention_tool_id`,
                        `remediation_id`,
                        `status_id`,
                        `risk_level_id`,
                        `comment`,
                        `uuid`)
                        VALUES
                        ("2019-03-06",
                        "test event",
                        {event_type_id},
                        {event_vector_id},
                        {event_prevention_tool_id},
                        {event_remediation_id},
                        {event_status_id},
                        {event_risk_level_id},
                        "blah blah blah",
                        "12345678-1234-1234-1234-123456789ab");""")
        db.commit()
        cursor.execute("SELECT id FROM events WHERE name='test event'")
        event_id = cursor.fetchone()[0]

        cursor.execute("""INSERT INTO `event_status` (`value`) VALUES ('CLOSED');""")
        db.commit()

        cursor.execute("SELECT id FROM events WHERE name='test event'")
        event_id = cursor.fetchone()[0]

        result = ace_api.update_event_status(event_id, 'CLOSED')
        assert result
        assert result['status'] == 'CLOSED'
