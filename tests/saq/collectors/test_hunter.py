from datetime import datetime, timedelta
import logging
import os
from queue import Queue
import shutil
from uuid import uuid4
import pytest

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.hunter import Hunt, HuntManager, HunterService, read_persistence_data
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION, G_DATA_DIR, ExecutionMode
from saq.environment import g_obj, get_data_dir
from saq.util.hashing import sha256
from saq.util.time import create_timedelta, local_time
from saq.util.uuid import storage_dir_from_uuid
from tests.saq.helpers import log_count, wait_for_log_count

def default_hunt(manager, enabled=True, name='test_hunt', description='Test Hunt', alert_type='test - alert',
                 frequency=create_timedelta('00:10'), tags=[ 'test_tag' ]):
    hunt = TestHunt(enabled=enabled, name=name, description=description,
                    alert_type=alert_type, frequency=frequency, tags=tags)
    hunt.manager = manager
    return hunt

class TestHunt(Hunt):
    __test__ = False
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = False

    def execute(self):
        logging.info(f"unit test execute marker: {self}")
        self.executed = True
        root_uuid = str(uuid4())
        root = RootAnalysis(
            uuid=root_uuid,
            storage_dir=storage_dir_from_uuid(root_uuid),
            desc='test',
            analysis_mode=ANALYSIS_MODE_CORRELATION,
            tool='test_tool',
            tool_instance='test_tool_instance',
            alert_type='test_type')
        root.initialize_storage()
        return [ Submission(root) ]

    def cancel(self):
        pass

@pytest.fixture
def rules_dir(tmpdir, datadir) -> str:
    temp_rules_dir = datadir / "test_rules"
    shutil.copytree("hunts/test/generic", temp_rules_dir)
    return str(temp_rules_dir)

@pytest.fixture
def manager_kwargs(rules_dir):
    yield { 'submission_queue': Queue(),
                'hunt_type': 'test',
                'rule_dirs': [rules_dir,],
                'hunt_cls': TestHunt,
                'concurrency_limit': 1,
                'persistence_dir': os.path.join(get_data_dir(), get_config()['collection']['persistence_dir']),
                'update_frequency': 60,
                'config': {},
                'execution_mode': ExecutionMode.SINGLE_SHOT}

@pytest.fixture
def hunter_service(manager_kwargs):
    hunter_service = HunterService()
    manager_kwargs["submission_queue"] = hunter_service.submission_queue
    hunter_service.add_hunt_manager(HuntManager(**manager_kwargs))
    yield hunter_service

@pytest.fixture
def hunter_service_single_threaded(hunter_service):
    # this is the default
    return hunter_service

@pytest.fixture
def hunter_service_multi_threaded(hunter_service):
    hunter_service.hunt_managers["test"].execution_mode = ExecutionMode.CONTINUOUS
    return hunter_service
    
@pytest.fixture(autouse=True, scope="function")
def setup():
    # delete all the existing hunt types
    hunt_type_sections = [_ for _ in get_config().sections() if _.startswith('hunt_type_')]
    for hunt_type_section in hunt_type_sections:
        del get_config()[hunt_type_section]

@pytest.mark.system
def test_start_stop(hunter_service_multi_threaded):
    hunter_service_multi_threaded.start()
    hunter_service_multi_threaded.wait_for_start()
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.integration
def test_add_hunt(manager_kwargs):
    hunter = HuntManager(**manager_kwargs)
    hunter.add_hunt(default_hunt(manager=hunter))
    assert len(hunter.hunts) == 1

@pytest.mark.integration
def test_hunt_persistence(manager_kwargs):
    hunter = HuntManager(**manager_kwargs)
    hunter.add_hunt(default_hunt(manager=hunter))
    hunter.hunts[0].last_executed_time = datetime(2019, 12, 10, 8, 21, 13)
    
    last_executed_time = read_persistence_data(hunter.hunts[0].type, hunter.hunts[0].name, 'last_executed_time')
    assert isinstance(last_executed_time, datetime)
    assert last_executed_time.year, 2019
    assert last_executed_time.month, 12
    assert last_executed_time.day, 10
    assert last_executed_time.hour, 8
    assert last_executed_time.minute, 21
    assert last_executed_time.second, 13

@pytest.mark.integration
def test_add_duplicate_hunt(manager_kwargs):
    # should not be allowed to add a hunt that already exists
    hunter = HuntManager(**manager_kwargs)
    hunter.add_hunt(default_hunt(manager=hunter))
    with pytest.raises(KeyError):
        hunter.add_hunt(default_hunt(manager=hunter))

@pytest.mark.integration
def test_remove_hunt(manager_kwargs):
    hunter = HuntManager(**manager_kwargs)
    hunt = hunter.add_hunt(default_hunt(manager=hunter))
    removed = hunter.remove_hunt(hunt)
    assert hunt.name == removed.name
    assert len(hunter.hunts) == 0

@pytest.mark.integration
def test_hunt_order(manager_kwargs):
    hunter = HuntManager(**manager_kwargs)
    # test initial hunt order
    # these are added in the wrong order but the should be sorted when we access them
    hunter.add_hunt(default_hunt(manager=hunter, name='test_hunt_3', frequency=create_timedelta('00:30')))
    hunter.add_hunt(default_hunt(manager=hunter, name='test_hunt_2', frequency=create_timedelta('00:20')))
    hunter.add_hunt(default_hunt(manager=hunter, name='test_hunt_1', frequency=create_timedelta('00:10')))

    # assume we've executed all of these hunts
    for hunt in hunter.hunts:
        hunt.last_executed_time = datetime.now()

    # now they should be in this order
    assert hunter.hunts[0].name == 'test_hunt_1'
    assert hunter.hunts[1].name == 'test_hunt_2'
    assert hunter.hunts[2].name == 'test_hunt_3'

@pytest.mark.integration
def test_hunt_execution_single_threaded(hunter_service_single_threaded):
    hunter_service_single_threaded.start_single_threaded()
    assert log_count('unit test execute marker: Hunt(Test 2[test])') ==  1

@pytest.mark.system
def test_hunt_execution_multi_threaded(hunter_service_multi_threaded):
    hunter_service_multi_threaded.start()
    hunter_service_multi_threaded.wait_for_start()
    wait_for_log_count('unit test execute marker: Hunt(Test 2[test])', 1)
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.integration
def test_load_hunts(manager_kwargs):
    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    for hunt in hunter.hunts:
        hunt.manager = hunter
    assert len(hunter.hunts) == 2
    assert isinstance(hunter.hunts[0], TestHunt)
    assert isinstance(hunter.hunts[1], TestHunt)

    for hunt in hunter.hunts:
        hunt.last_executed_time = datetime.now()

    assert hunter.hunts[1].enabled
    assert hunter.hunts[1].name == 'unit_test_1'
    assert hunter.hunts[1].description == 'Unit Test Description 1'
    assert hunter.hunts[1].type == 'test'
    assert hunter.hunts[1].alert_type == 'test - alert'
    assert hunter.hunts[1].analysis_mode == ANALYSIS_MODE_CORRELATION
    assert isinstance(hunter.hunts[1].frequency, timedelta)
    assert hunter.hunts[1].tags == ['tag1', 'tag2']

    assert hunter.hunts[0].enabled
    # the second one is missing the name so the name is auto generated
    assert hunter.hunts[0].name == 'Test 2'
    assert hunter.hunts[0].description == 'Unit Test Description 2'
    assert hunter.hunts[0].type == 'test'
    # the second one is missing the alert_type so this is auto generated
    assert hunter.hunts[0].alert_type == 'hunter - test'
    assert hunter.hunts[0].analysis_mode == ANALYSIS_MODE_ANALYSIS
    assert isinstance(hunter.hunts[0].frequency, timedelta)
    assert hunter.hunts[0].tags == ['tag1', 'tag2']

@pytest.mark.integration
def test_fix_invalid_hunt(rules_dir, manager_kwargs):
    failed_yaml_path = os.path.join(rules_dir, 'test_3.yaml')
    with open(failed_yaml_path, 'w') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  #frequency: '00:00:01' <-- missing frequency
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    assert len(hunter.hunts) == 2
    assert len(hunter.failed_yaml_files) == 1
    assert failed_yaml_path in hunter.failed_yaml_files
    assert hunter.failed_yaml_files[failed_yaml_path][0] == os.path.getmtime(failed_yaml_path)
    assert hunter.failed_yaml_files[failed_yaml_path][1] == os.path.getsize(failed_yaml_path)
    assert hunter.failed_yaml_files[failed_yaml_path][2] == sha256(failed_yaml_path)

    assert not hunter.reload_hunts_flag
    hunter.check_hunts()
    assert not hunter.reload_hunts_flag

    with open(failed_yaml_path, 'w') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  tags:
    - tag1
    - tag2
""")

    hunter.check_hunts()
    assert hunter.reload_hunts_flag
    hunter.reload_hunts()
    assert len(hunter.hunts) == 3
    assert len(hunter.failed_yaml_files) == 0

@pytest.mark.integration
def test_load_hunts_wrong_type(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'hunt_invalid.yaml'), 'w') as fp:
        fp.write("""rule:
  enabled: yes
  name: test_wrong_type
  description: Testing Wrong Type
  type: unknown
  alert_type: test - alert
  frequency: '00:00:01'
  tags:
    - tag1
    - tag2
""")


    with open(os.path.join(rules_dir, 'hunt_valid.yaml'), 'w') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    for hunt in hunter.hunts:
        hunt.manager = hunter

    assert len(hunter.hunts) == 1
    assert not hunter.reload_hunts_flag

    # nothing has changed so this should still be False
    hunter.check_hunts()
    assert not hunter.reload_hunts_flag

@pytest.mark.integration
def test_hunt_disabled(manager_kwargs):
    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    hunter.hunts[0].enabled = True
    hunter.hunts[1].enabled = True

    assert all([not hunt.executed for hunt in hunter.hunts])
    assert hunter.hunts[0].last_executed_time is None
    assert hunter.hunts[1].last_executed_time is None
    assert all([hunt.ready for hunt in hunter.hunts])
    hunter.execute()
    hunter.manager_control_event.set()
    hunter.wait_control_event.set()
    hunter.wait()
    assert all([hunt.executed for hunt in hunter.hunts])

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    hunter.hunts[0].enabled = False
    hunter.hunts[1].enabled = False

    assert all([not hunt.executed for hunt in hunter.hunts])
    hunter.execute()
    hunter.execute()
    hunter.manager_control_event.set()
    hunter.wait_control_event.set()
    hunter.wait()
    assert all([not hunt.executed for hunt in hunter.hunts])

@pytest.mark.system
def test_reload_hunts_on_yaml_modified(rules_dir, hunter_service_multi_threaded):
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 1)
    wait_for_log_count('loaded Hunt(Test 2[test]) from', 1)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'a') as fp:
        fp.write('\n\n# modified')

    wait_for_log_count('detected modification to', 1, 5)
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 2)
    wait_for_log_count('loaded Hunt(Test 2[test]) from', 2)
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.system
def test_reload_hunts_on_deleted(rules_dir, hunter_service_multi_threaded):
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 1)
    wait_for_log_count('loaded Hunt(Test 2[test]) from', 1)
    os.remove(os.path.join(rules_dir, 'test_1.yaml'))
    wait_for_log_count('detected modification to', 1, 5)
    wait_for_log_count('loaded Hunt(Test 2[test]) from', 2)
    assert log_count('loaded Hunt(unit_test_1[test]) from') == 1
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.system
def test_reload_hunts_on_new(rules_dir, hunter_service_multi_threaded):
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 1)
    wait_for_log_count('loaded Hunt(Test 2[test]) from', 1)
    with open(os.path.join(rules_dir, 'test_3.yaml'), 'w') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  frequency: '00:00:10'
  tags:
    - tag1
    - tag2
""")

    wait_for_log_count('detected new hunt yaml', 1, 5)
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 2)
    wait_for_log_count('loaded Hunt(Test 2[test]) from', 2)
    wait_for_log_count('loaded Hunt(unit_test_3[test]) from', 1)
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.integration
def test_valid_cron_schedule(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'a') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '*/1 * * * *'
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    assert len(hunter.hunts) == 1
    assert isinstance(hunter.hunts[0], TestHunt)
    assert hunter.hunts[0].frequency is None
    assert hunter.hunts[0].cron_schedule == '*/1 * * * *'

@pytest.mark.integration
def test_invalid_cron_schedule(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'a') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '*/1 * * *'
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    assert len(hunter.hunts) == 0
    assert len(hunter.failed_yaml_files) == 1

@pytest.mark.integration
def test_hunt_suppression(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'a') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  suppression: '00:01:00'
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    assert len(hunter.hunts) == 1
    assert isinstance(hunter.hunts[0], TestHunt)
    assert hunter.hunts[0].suppression is not None
    assert hunter.hunts[0].suppression_end is None

    hunter.execute()
    hunter.manager_control_event.set()
    hunter.wait_control_event.set()
    hunter.wait()
    assert hunter.hunts[0].executed
    # should have suppression
    assert hunter.hunts[0].suppression_end is not None
    # should not be ready
    assert not hunter.hunts[0].ready

@pytest.mark.unit
def test_initialize_last_execution_time(monkeypatch, tmpdir):
    class MockManager:
        @property
        def hunt_type(self):
            return "test"

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    p_dir = data_dir / "p"
    p_dir.mkdir()
    monkeypatch.setattr(g_obj(G_DATA_DIR), "value", str(data_dir))
    monkeypatch.setitem(get_config()["collection"], "persistence_dir", "p")
    #monkeypatch.setattr(saq, "CONFIG", { "collection": { "persistence_dir": "p" } })
    hunt = Hunt(manager=MockManager(), name="test")
    hunt.frequency = timedelta(seconds=10)
    # shoule be ready
    assert hunt.next_execution_time <= local_time()
    assert hunt.ready

@pytest.mark.unit
def test_initialize_last_execution_time_cron(monkeypatch, tmpdir):
    class MockManager:
        @property
        def hunt_type(self):
            return "test"

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    p_dir = data_dir / "p"
    p_dir.mkdir()
    monkeypatch.setattr(g_obj(G_DATA_DIR), "value", str(data_dir))
    monkeypatch.setitem(get_config()["collection"], "persistence_dir", "p")
    #monkeypatch.setattr(saq, "CONFIG", { "collection": { "persistence_dir": "p" } })
    hunt = Hunt(manager=MockManager(), name="test")
    hunt.cron_schedule = "*/10 * * * *"
    # shoule be ready
    assert hunt.next_execution_time <= local_time()
    assert hunt.ready

@pytest.mark.integration
def test_load_hunt_with_instance_types(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'w') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  instance_types:
    - production
    - development
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    assert len(hunter.hunts) == 1
    assert isinstance(hunter.hunts[0], TestHunt)
    assert hunter.hunts[0].instance_types == ['production', 'development']

@pytest.mark.integration
def test_load_hunt_without_instance_types(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'w') as fp:
        fp.write("""rule:
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    assert len(hunter.hunts) == 1
    assert isinstance(hunter.hunts[0], TestHunt)
    assert hunter.hunts[0].instance_types == []

@pytest.mark.integration
def test_is_valid_instance_type_empty(manager_kwargs, monkeypatch):
    # when instance_types is empty, hunt should be valid for any instance type
    monkeypatch.setitem(get_config()["global"], "instance_type", "production")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter)
    hunt.instance_types = []

    assert hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_is_valid_instance_type_matching(manager_kwargs, monkeypatch):
    # hunt with instance_types=['production'] should be valid for production instance
    monkeypatch.setitem(get_config()["global"], "instance_type", "production")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter)
    hunt.instance_types = ['production', 'development']

    assert hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_is_valid_instance_type_case_insensitive(manager_kwargs, monkeypatch):
    # instance type matching should be case insensitive
    monkeypatch.setitem(get_config()["global"], "instance_type", "Production")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter)
    hunt.instance_types = ['PRODUCTION', 'development']

    assert hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_is_valid_instance_type_non_matching(manager_kwargs, monkeypatch):
    # hunt with instance_types=['production'] should not be valid for development instance
    monkeypatch.setitem(get_config()["global"], "instance_type", "development")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter)
    hunt.instance_types = ['production']

    assert not hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_hunt_execution_skips_invalid_instance_type(manager_kwargs, monkeypatch):
    # hunts with invalid instance types should not execute
    monkeypatch.setitem(get_config()["global"], "instance_type", "production")

    hunter = HuntManager(**manager_kwargs)

    # add a hunt valid for production
    valid_hunt = default_hunt(manager=hunter, name='valid_hunt')
    valid_hunt.instance_types = ['production']
    hunter.add_hunt(valid_hunt)

    # add a hunt valid for development only
    invalid_hunt = default_hunt(manager=hunter, name='invalid_hunt')
    invalid_hunt.instance_types = ['development']
    hunter.add_hunt(invalid_hunt)

    # add a hunt with no instance type restriction
    unrestricted_hunt = default_hunt(manager=hunter, name='unrestricted_hunt')
    unrestricted_hunt.instance_types = []
    hunter.add_hunt(unrestricted_hunt)

    # execute all hunts
    hunter.execute()
    hunter.manager_control_event.set()
    hunter.wait_control_event.set()
    hunter.wait()

    # valid_hunt and unrestricted_hunt should have executed
    assert valid_hunt.executed
    assert unrestricted_hunt.executed

    # invalid_hunt should not have executed
    assert not invalid_hunt.executed