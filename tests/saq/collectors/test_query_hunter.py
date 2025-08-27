import configparser
from datetime import datetime, timedelta
import logging
import os
from queue import Queue
import shutil
import pytest

from saq.collectors.base_collector import CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.hunter import HuntManager, HunterCollector, HunterService, read_persistence_data
from saq.collectors.query_hunter import QueryHunt, _compute_directive_value
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, F_HUNT, G_DATA_DIR
from saq.environment import g_obj, get_data_dir
from saq.util.time import create_timedelta, local_time
from tests.saq.helpers import log_count, wait_for_log_count

class TestQueryHunt(QueryHunt):
    __test__ = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exec_start_time = None
        self.exec_end_time = None

    def execute_query(self, start_time, end_time):
        logging.info(f"executing query {self.query} {start_time} {end_time}")
        self.exec_start_time = start_time
        self.exec_end_time = end_time
        return []

    def cancel(self):
        pass

def default_hunt(enabled=True, 
                 name='test_hunt', 
                 description='Test Hunt', 
                 alert_type='test - query',
                 frequency=create_timedelta('00:10'), 
                 tags=[ 'test_tag' ],
                 search_query_path='hunts/test/query/test_1.query',
                 time_range=create_timedelta('00:10'),
                 full_coverage=True,
                 offset=None,
                 group_by='field1',
                 observable_mapping={},
                 temporal_fields=[],
                 directives={}):
    return TestQueryHunt(enabled=enabled, 
                         name=name, 
                         description=description,
                         alert_type=alert_type,
                         frequency=frequency, 
                         tags=tags,
                         search_query_path=search_query_path,
                         time_range=time_range,
                         full_coverage=full_coverage,
                         offset=offset,
                         group_by=group_by,
                         observable_mapping=observable_mapping,
                         temporal_fields=temporal_fields,
                         directives=directives)

@pytest.fixture
def manager_kwargs(rules_dir):
    return { 'submission_queue': Queue(),
                'hunt_type': 'test_query',
                'rule_dirs': [ rules_dir ],
                'hunt_cls': TestQueryHunt,
                'concurrency_limit': 1,
                'persistence_dir': os.path.join(get_data_dir(), get_config()['collection']['persistence_dir']),
                'update_frequency': 60 ,
                'config': {}}

@pytest.fixture
def rules_dir(tmpdir, datadir) -> str:
    temp_rules_dir = datadir / "test_rules"
    shutil.copytree("hunts/test/generic", temp_rules_dir)
    return str(temp_rules_dir)

@pytest.fixture(autouse=True, scope="function")
def setup(rules_dir):
    get_config().add_section('hunt_type_test_query')
    s = get_config()['hunt_type_test_query']
    s['module'] = 'tests.saq.collectors.test_query_hunter'
    s['class'] = 'TestQueryHunt'
    s['rule_dirs'] = rules_dir
    s['hunt_type'] = 'test_query'
    s['concurrency_limit'] = "1"
    s['update_frequency'] = "60"

    test_ini_path = os.path.join(rules_dir, 'test_1.ini')
    with open(test_ini_path, 'w') as fp:
        fp.write(f"""
[rule]
enabled = yes
name = query_test_1
description = Query Test Description 1
type = test_query
alert_type = test - query
frequency = 00:01:00
tags = tag1, tag2

time_range = 00:01:00
max_time_range = 01:00:00
offset = 00:05:00
full_coverage = yes
group_by = field1
search = {rules_dir}/test_1.query
use_index_time = yes

[observable_mapping]
src_ip = ipv4
dst_ip = ipv4

[temporal_fields]
src_ip = yes
dst_ip = yes

[directives]
""")

    test_query_path = os.path.join(rules_dir, 'test_1.query')
    with open(test_query_path, 'w') as fp:
        fp.write('Test query.')

@pytest.mark.integration
def test_load_hunt_ini(manager_kwargs):
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    hunt = manager.hunts[0]
    assert hunt.enabled
    assert hunt.name == 'query_test_1'
    assert hunt.description == 'Query Test Description 1'
    assert hunt.manager == manager
    assert hunt.alert_type == 'test - query'
    assert hunt.frequency == create_timedelta('00:01:00')
    assert hunt.tags == ['tag1', 'tag2']
    assert hunt.time_range == create_timedelta('00:01:00')
    assert hunt.max_time_range == create_timedelta('01:00:00')
    assert hunt.offset == create_timedelta('00:05:00')
    assert hunt.full_coverage
    assert hunt.group_by == 'field1'
    assert hunt.query == 'Test query.'
    assert hunt.use_index_time
    assert hunt.observable_mapping == { 'src_ip': 'ipv4', 'dst_ip': 'ipv4' }
    assert hunt.temporal_fields == { 'src_ip': True, 'dst_ip': True }

@pytest.mark.integration
def test_load_query_inline(rules_dir, manager_kwargs):
    test_ini_path = os.path.join(rules_dir, 'test_1.ini')
    with open(test_ini_path, 'w') as fp:
        fp.write("""
[rule]
enabled = yes
name = query_test_1
description = Query Test Description 1
type = test_query
alert_type = test - query
frequency = 00:01:00
tags = tag1, tag2

time_range = 00:01:00
max_time_range = 01:00:00
offset = 00:05:00
full_coverage = yes
group_by = field1
query = Test query.
use_index_time = yes

[observable_mapping]
src_ip = ipv4
dst_ip = ipv4

[temporal_fields]
src_ip = yes
dst_ip = yes

[directives]
""")
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    hunt = manager.hunts[0]
    assert hunt.enabled
    assert hunt.query == 'Test query.'

@pytest.mark.integration
def test_load_multi_line_query_inline(rules_dir, manager_kwargs):
    test_ini_path = os.path.join(rules_dir, 'test_1.ini')
    with open(test_ini_path, 'w') as fp:
        fp.write("""
[rule]
enabled = yes
name = query_test_1
description = Query Test Description 1
type = test_query
alert_type = test - query
frequency = 00:01:00
tags = tag1, tag2

time_range = 00:01:00
max_time_range = 01:00:00
offset = 00:05:00
full_coverage = yes
group_by = field1
query = 
    This is a multi line query.
    How about that?
use_index_time = yes

[observable_mapping]
src_ip = ipv4
dst_ip = ipv4

[temporal_fields]
src_ip = yes
dst_ip = yes

[directives]
""")
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    hunt = manager.hunts[0]
    assert hunt.enabled
    assert hunt.query == """\nThis is a multi line query.\nHow about that?"""

@pytest.mark.integration
def test_reload_hunts_on_search_modified(rules_dir, manager_kwargs):
    manager_kwargs['update_frequency'] = 1
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert log_count('loaded Hunt(query_test_1[test_query]) from') == 1
    with open(os.path.join(rules_dir, 'test_1.query'), 'a') as fp:
        fp.write('\n\n; modified')

    test_query_path = os.path.join(rules_dir, 'test_1.query')
    os.utime(test_query_path, (os.path.getatime(test_query_path), (datetime.now() - timedelta(seconds=5)).timestamp()))

    manager.check_hunts()
    assert log_count('detected modification to') == 1
    assert manager.reload_hunts_flag
    manager.reload_hunts()
    assert log_count('loaded Hunt(query_test_1[test_query]) from') == 2

@pytest.mark.system
def test_start_stop():
    hunter_service = HunterService()
    hunter_service.start()
    wait_for_log_count('started Hunt Manager(test_query)', 1)

    # verify the rules where loaded
    assert log_count('loading hunt from') == 2
    assert log_count('loaded Hunt(query_test_1[test_query])') == 1

    # wait for the hunt to execute
    wait_for_log_count('executing query', 1)

    # we should have persistence data for both the last_executed_time and last_end_time fields
    assert isinstance(read_persistence_data('test_query', 'query_test_1', 'last_executed_time'), datetime) # last_executed_time
    assert isinstance(read_persistence_data('test_query', 'query_test_1', 'last_end_time'), datetime) # last_end_time

    hunter_service.stop()
    hunter_service.wait()

@pytest.mark.integration
def test_full_coverage(manager_kwargs):
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(time_range=create_timedelta('01:00:00'), 
                        frequency=create_timedelta('01:00:00'))
    hunt.manager = manager
    manager.add_hunt(hunt)

    # first test that the start time and end time are correct for normal operation
    # for first-time hunt execution
    assert hunt.ready

    # now put the last time we executed to 5 minutes ago
    # ready should return False
    hunt.last_executed_time = local_time() - timedelta(minutes=5)
    assert not hunt.ready

    # now put the last time we executed to 65 minutes ago
    # ready should return True
    hunt.last_executed_time = local_time() - timedelta(minutes=65)
    assert hunt.ready

    # set the last time we executed to 3 hours ago
    hunt.last_executed_time = local_time() - timedelta(hours=3)
    # and the last end date to 2 hours ago
    hunt.last_end_time = local_time() - timedelta(hours=2)
    # so now we have 2 hours to cover under full coverage
    # ready should return True, start should be 3 hours ago and end should be 2 hours ago
    assert hunt.ready
    assert hunt.start_time == hunt.last_end_time
    assert hunt.end_time == hunt.last_end_time + hunt.time_range

    # now let's pretend that we just executed that
    # at this point, the last_end_time becomes the end_time
    hunt.last_end_time = hunt.end_time
    # and the last_executed_time becomes now
    hunt.last_executed_time = local_time()
    # at this point the hunt should still be ready because we're not caught up yet
    #self.assertTrue(hunt.ready)

    # now give the hunt the ability to cover 2 hours instead of 1 to get caught up
    hunt.max_time_range = create_timedelta('02:00:00')
    # set the last time we executed to 3 hours ago
    hunt.last_executed_time = local_time() - timedelta(hours=3)
    # and the last end date to 2 hours ago
    hunt.last_end_time = local_time() - timedelta(hours=2)
    # now the difference between the stop and stop should be 2 hours instead of one
    assert hunt.end_time - hunt.start_time >= hunt.max_time_range

    # set the last time we executed to 3 hours ago
    hunt.last_executed_time = local_time() - timedelta(hours=3)
    # and the last end date to 2 hours ago
    hunt.last_end_time = local_time() - timedelta(hours=2)
    # so now we have 2 hours to cover but let's turn off full coverage
    hunt.full_coverage = False
    # it should be ready to run
    assert hunt.ready
    # and the start time should be now - time_range

@pytest.mark.integration
def test_offset(manager_kwargs):
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(time_range=create_timedelta('01:00:00'), 
                        frequency=create_timedelta('01:00:00'),
                        offset=create_timedelta('00:30:00'))
    hunt.manager = manager
    manager.add_hunt(hunt)

    # set the last time we executed to 3 hours ago
    hunt.last_executed_time = local_time() - timedelta(hours=3)
    # and the last end date to 2 hours ago
    target_start_time = hunt.last_end_time = local_time() - timedelta(hours=2)
    assert hunt.ready
    hunt.execute()

    # the times passed to hunt.execute_query should be 30 minutes offset
    assert target_start_time - hunt.offset == hunt.exec_start_time
    assert hunt.last_end_time - hunt.offset == hunt.exec_end_time

@pytest.mark.integration
def test_missing_query_file(rules_dir, manager_kwargs):
    test_query_path = os.path.join(rules_dir, 'test_1.query')
    os.remove(test_query_path)
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 0
    assert len(manager.failed_ini_files) == 1

    assert not manager.reload_hunts_flag
    manager.check_hunts()
    assert not manager.reload_hunts_flag

    with open(test_query_path, 'w') as fp:
        fp.write('Test query.')

    manager.check_hunts()
    assert not manager.reload_hunts_flag

_local_time = local_time()
def mock_local_time():
    return _local_time

@pytest.mark.unit
@pytest.mark.parametrize("field_name,directives,event,expected_result", [
    ("name", {}, None, []), # no directives
    ("name", {"name":["value"]}, None, ["value"]), # simple directive
    ("name", {"name":["value_{ip}"]}, {"ip": "test"}, ["value_test"]), # single directive with format
    ("name", {"name":["value_{ips}"]}, {"ip": "test"}, []), # single directive missing key
    ("name", {"name":["test", "value_{ips}"]}, {"ip": "test"}, ["test"]), # directive missing key and simple directive
])
def test_compute_directive_value(field_name, directives, event, expected_result, datadir):
    assert _compute_directive_value(field_name, directives, event=event) == expected_result

class MockManager:
    @property
    def hunt_type(self):
        return "test"

@pytest.mark.unit
def test_query_hunter_end_time(monkeypatch, tmpdir):

    import saq.collectors.query_hunter
    monkeypatch.setattr(saq.collectors.query_hunter, "local_time", mock_local_time)

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    monkeypatch.setattr(g_obj(G_DATA_DIR), "value", str(data_dir))
    mock_config = configparser.ConfigParser()
    mock_config.read_string("""[collection]
                            persistence_dir = p
                            """)
    hunt = QueryHunt(manager=MockManager(), name="test")
    assert hunt.end_time

    # full coverage end time
    hunt.full_coverage = True
    hunt.last_end_time = mock_local_time() - timedelta(hours=1)
    hunt.time_range = timedelta(hours=1)
    assert hunt.end_time == hunt.last_end_time + hunt.time_range

    # full coverage, we're behind by one hour and max_time_range is not set
    hunt.last_end_time = mock_local_time() - timedelta(hours=2)
    assert hunt.end_time == hunt.last_end_time + timedelta(hours=1) # can only go in increments of time_range

    # full coverage, we're behind by one hour and max_time_range is set
    hunt.last_end_time = mock_local_time() - timedelta(hours=2)
    hunt.max_time_range = timedelta(hours=8)
    assert hunt.end_time == hunt.last_end_time + timedelta(hours=2) # can go up to max time range

    # but no more than that at a time
    hunt.last_end_time = mock_local_time() - timedelta(hours=9)
    assert hunt.end_time == hunt.last_end_time + timedelta(hours=8) # can go up to max time range

@pytest.mark.unit
def test_query_hunter_ready(monkeypatch, tmpdir):
    data_dir = tmpdir / "data"
    data_dir.mkdir()
    monkeypatch.setattr(g_obj(G_DATA_DIR), "value", str(data_dir))
    mock_config = configparser.ConfigParser()
    mock_config.read_string("""[collection]
                            persistence_dir = p
                            """)
    #monkeypatch.setattr(saq, "CONFIG", { "collection": { "persistence_dir": "p" } })
    hunt = QueryHunt(manager=MockManager(), name="test")

    # we just ran and our frequency is sent to an hour
    hunt.last_executed_time = mock_local_time()
    hunt.frequency = timedelta(hours=1)
    assert not hunt.ready

    # we ran an hour ago and frequency is set to an hour
    hunt.last_executed_time = mock_local_time() - timedelta(hours=1)
    hunt.frequency = timedelta(hours=1)
    assert hunt.ready

    # full coverage testing
    # we ran 2 hours ago, range is set to an hour and frequency is set to an hour
    hunt.full_coverage = True
    hunt.last_executed_time = mock_local_time() - timedelta(hours=2)
    hunt.frequency = timedelta(hours=1)
    assert hunt.ready

    # this logic is no longer supported
    #hunt.last_executed_time = mock_local_time()
    #hunt.last_end_time = mock_local_time() - timedelta(hours=2)
    #hunt.frequency = timedelta(hours=1)
    #hunt.time_range = timedelta(hours=1)
    #assert hunt.ready

@pytest.mark.unit
def test_process_query_results(monkeypatch):
    import saq.collectors.query_hunter
    monkeypatch.setattr(saq.collectors.query_hunter, "local_time", mock_local_time)

    hunt = QueryHunt(manager=MockManager(), name="test")
    hunt.analysis_mode = ANALYSIS_MODE_CORRELATION
    hunt.observable_mapping = {
        "src": "ipv4"
    }
    hunt.alert_type = "test-type"
    hunt.queue = "test-queue"
    hunt.description = "test instructions"
    hunt.playbook_url = "http://playbook"
    hunt.directives = { }
    hunt.temporal_fields = { }

    assert hunt.process_query_results(None) is None
    assert not hunt.process_query_results([])
    submissions = hunt.process_query_results([{}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]
    assert submission.root.description == "test"
    assert submission.root.analysis_mode == hunt.analysis_mode
    assert submission.root.tool == "hunter-test"
    assert submission.root.tool_instance == "localhost"
    assert submission.root.alert_type == hunt.alert_type
    assert submission.root.event_time == mock_local_time()
    assert isinstance(submission.root.details, list)
    assert submission.root.details[1] == {}
    assert submission.root.observables
    hunt_observable = submission.root.get_observables_by_type(F_HUNT)[0]
    assert hunt_observable.value == "test"
    assert submission.root.tags == []
    #assert submission.root.files == []
    assert submission.root.queue == hunt.queue
    assert submission.root.instructions == hunt.description
    assert submission.root.extensions == { "playbook_url": hunt.playbook_url }

    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]
    assert len(submission.root.observables) == 2

    hunt.group_by = "src"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "1.2.3.5"},
    ])
    assert submissions
    assert len(submissions) == 2
    for submission in submissions:
        assert len(submission.root.observables) == 2
        assert submission.root.description.endswith(": 1.2.3.4 (1 events)") or submission.root.description.endswith(": 1.2.3.5 (1 events)")

    hunt.group_by = "dst"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "1.2.3.5"},
    ])
    assert submissions
    assert len(submissions) == 2
    for submission in submissions:
        assert len(submission.root.observables) == 2

    hunt.group_by = "ALL"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "1.2.3.5"},
    ])
    assert submissions
    assert len(submissions) == 1
    for submission in submissions:
        assert len(submission.root.observables) == 3