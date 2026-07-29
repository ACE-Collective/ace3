from datetime import datetime, timedelta
import logging
import os
from queue import Queue
import shutil
from uuid import uuid4
import pytest
from pydantic import ValidationError

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.hunter import Hunt, HuntManager, HunterService, read_persistence_data
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION, ExecutionMode
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.error.remote import RemoteApiError
from saq.logging import DEFAULT_TRANSACTION_ID, get_transaction_id
from saq.util.hashing import sha256
from saq.util.time import local_time
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import log_count, wait_for_log_count

def default_hunt_config(**kwargs):
    config_kwargs = {
        "uuid": kwargs.get("uuid", str(uuid4())),
        "enabled": kwargs.get("enabled", True),
        "name": kwargs.get("name", 'test_hunt'),
        "type": kwargs.get("type", 'test'),
        "description": kwargs.get("description", 'Test Hunt'),
        "alert_type": kwargs.get("alert_type", 'test - alert'),
        "frequency": kwargs.get("frequency", '00:10'),
        "tags": kwargs.get("tags", [ 'test_tag' ]),
        "instance_types": kwargs.get("instance_types", ["unittest"]),
        **kwargs
    }
    return HuntConfig(**config_kwargs)


@pytest.mark.unit
def test_hunt_config_rejects_extra_field():
    with pytest.raises(ValidationError) as exc_info:
        default_hunt_config(typo_field="oops")
    assert "typo_field" in str(exc_info.value)


@pytest.mark.unit
@pytest.mark.parametrize("value,expected", [
    ("alice", ["alice"]),
    (["alice", "bob"], ["alice", "bob"]),
    (None, []),
])
def test_hunt_config_author_normalization(value, expected):
    config = default_hunt_config(author=value)
    assert config.author == expected

def default_hunt(
    manager,
    uuid=(str(uuid4())),
    enabled=True,
    name='test_hunt',
    description='Test Hunt',
    alert_type='test - alert',
    frequency='00:10',
    tags=[ 'test_tag' ],
    instance_types=["unittest"],
    **kwargs):

    return TestHunt(manager=manager, config=HuntConfig(
        uuid=uuid,
        enabled=enabled,
        name=name,
        type='test',
        description=description,
        alert_type=alert_type,
        frequency=frequency,
        tags=tags,
        instance_types=instance_types,
        **kwargs))

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
            storage_dir=get_storage_dir(root_uuid),
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
    shutil.copytree("tests/data/hunts/test/generic", temp_rules_dir)
    return str(temp_rules_dir)

@pytest.fixture
def manager_kwargs(rules_dir):
    yield { 'submission_queue': Queue(),
                'hunt_type': 'test',
                'rule_dirs': [rules_dir,],
                'hunt_cls': TestHunt,
                'concurrency_limit': 1,
                'persistence_dir': os.path.join(get_data_dir(), get_config().collection.persistence_dir),
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
    get_config().clear_hunt_type_configs()

@pytest.mark.system
def test_start_stop(hunter_service_multi_threaded):
    hunter_service_multi_threaded.start()
    hunter_service_multi_threaded.wait_for_start()
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.integration
def test_persistence_defers_execution_on_reload(hunter_service_single_threaded, manager_kwargs):
    # Execute all hunts once to write persistence (last_executed_time, etc.)
    hunter_service_single_threaded.start_single_threaded()
    # Validate they executed at least once (establishes persisted state)
    assert log_count('unit test execute marker: Hunt(unit_test_1[test])') >= 1
    assert log_count('unit test execute marker: Hunt(unit_test_2[test])') >= 1

    # Simulate a "restart": construct a fresh manager and load hunts
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) >= 1

    # The hunt 'unit_test_1' has a frequency of 10s; immediately after restart it should NOT be ready
    hunt_names = {h.name: h for h in manager.hunts}
    if 'unit_test_1' in hunt_names:
        assert not hunt_names['unit_test_1'].ready
    else:
        # If the expected hunt isn't present, fail explicitly (test fixture/rules issue)
        assert False, "Expected hunt 'unit_test_1' not found after reload"

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
    hunter.add_hunt(default_hunt(manager=hunter, name='test_hunt_3', frequency='00:30'))
    hunter.add_hunt(default_hunt(manager=hunter, name='test_hunt_2', frequency='00:20'))
    hunter.add_hunt(default_hunt(manager=hunter, name='test_hunt_1', frequency='00:10'))

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
    # both of these tests should run
    assert log_count('unit test execute marker: Hunt(unit_test_1[test])') ==  1
    assert log_count('unit test execute marker: Hunt(unit_test_2[test])') ==  1

@pytest.mark.system
def test_hunt_execution_multi_threaded(hunter_service_multi_threaded):
    hunter_service_multi_threaded.start()
    hunter_service_multi_threaded.wait_for_start()
    wait_for_log_count('unit test execute marker: Hunt(unit_test_1[test])', 1)
    wait_for_log_count('unit test execute marker: Hunt(unit_test_2[test])', 1)
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
    assert hunter.hunts[0].name == 'unit_test_2'
    assert hunter.hunts[0].description == 'Unit Test Description 2'
    assert hunter.hunts[0].type == 'test'
    assert hunter.hunts[0].alert_type == 'test - alert'
    assert hunter.hunts[0].analysis_mode == ANALYSIS_MODE_ANALYSIS
    assert isinstance(hunter.hunts[0].frequency, timedelta)
    assert hunter.hunts[0].tags == ['tag1', 'tag2']

@pytest.mark.integration
def test_fix_invalid_hunt(rules_dir, manager_kwargs):
    failed_yaml_path = os.path.join(rules_dir, 'test_3.yaml')
    with open(failed_yaml_path, 'w') as fp:
        fp.write("""rule:
  uuid: d38b8582-249c-4a35-8359-20854603aed6
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  #frequency: '00:00:01' <-- missing frequency
  instance_types:
    - unittest
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
  uuid: d38b8582-249c-4a35-8359-20854603aed6
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  instance_types:
    - unittest
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
  uuid: c5a2bddc-a719-46d9-b782-001232e07553
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
  uuid: c5a2bddc-a719-46d9-b782-001232e07553
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  instance_types:
    - unittest
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
    hunter.hunts[0].config.enabled = True
    hunter.hunts[1].config.enabled = True

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
    hunter.hunts[0].config.enabled = False
    hunter.hunts[1].config.enabled = False

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
    wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 1)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'a') as fp:
        fp.write('\n\n# modified')

    wait_for_log_count('detected modification to', 1, 5)
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 2)
    wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 2)
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.system
def test_reload_hunts_on_deleted(rules_dir, hunter_service_multi_threaded):
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 1)
    wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 1)
    os.remove(os.path.join(rules_dir, 'test_1.yaml'))
    wait_for_log_count('detected modification to', 1, 5)
    wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 2)
    assert log_count('loaded Hunt(unit_test_1[test]) from') == 1
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.system
def test_reload_hunts_on_new(rules_dir, hunter_service_multi_threaded):
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 1)
    wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 1)
    with open(os.path.join(rules_dir, 'test_3.yaml'), 'w') as fp:
        fp.write("""rule:
  uuid: 245d0de0-9cc4-4a02-b9ce-07359dc858bf
  enabled: yes
  name: unit_test_3
  description: Unit Test Description 3
  type: test
  alert_type: test - alert
  frequency: '00:00:10'
  instance_types:
    - unittest
  tags:
    - tag1
    - tag2
""")

    wait_for_log_count('detected new hunt yaml', 1, 5)
    wait_for_log_count('loaded Hunt(unit_test_1[test]) from', 2)
    wait_for_log_count('loaded Hunt(unit_test_2[test]) from', 2)
    wait_for_log_count('loaded Hunt(unit_test_3[test]) from', 1)
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.system
def test_reload_hunts_on_included_file_modified(rules_dir, hunter_service_multi_threaded):
    """Test that modifying an included file causes the hunt to reload."""
    # Create an includes subdirectory
    includes_dir = os.path.join(rules_dir, 'includes')
    os.makedirs(includes_dir, exist_ok=True)
    
    # Create an included file
    included_file = os.path.join(includes_dir, 'test_include.include.yaml')
    with open(included_file, 'w') as fp:
        fp.write("""rule:
  tags:
    - included_tag_1
    - included_tag_2
  description: Included description
""")
    
    # Create a hunt file that includes the above file
    hunt_file = os.path.join(rules_dir, 'test_with_include.yaml')
    with open(hunt_file, 'w') as fp:
        fp.write("""include:
  - includes/test_include.include.yaml
rule:
  uuid: 8c6f3381-5b2e-4f67-9c1d-0e4f5a6b7c8d
  enabled: yes
  name: test_with_include
  description: Test Hunt With Include
  type: test
  alert_type: test - alert
  frequency: '00:00:10'
  instance_types:
    - unittest
  tags:
    - main_tag
""")
    
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(test_with_include[test]) from', 1)
    
    # Verify the hunt was loaded with the included tags
    manager = hunter_service_multi_threaded.hunt_managers["test"]
    hunt = next((h for h in manager.hunts if h.name == 'test_with_include'), None)
    assert hunt is not None
    assert 'included_tag_1' in hunt.tags
    assert 'included_tag_2' in hunt.tags
    assert 'main_tag' in hunt.tags
    
    # Modify the included file
    with open(included_file, 'a') as fp:
        fp.write('\n  # modified included file')
    
    # Wait for the modification to be detected and the hunt to reload
    wait_for_log_count('detected modification to', 1, 5)
    wait_for_log_count('loaded Hunt(test_with_include[test]) from', 2)
    
    # Verify the hunt was reloaded (the hunt object should still exist)
    hunt_after = next((h for h in manager.hunts if h.name == 'test_with_include'), None)
    assert hunt_after is not None
    
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.system
def test_reload_hunts_on_nested_included_file_modified(rules_dir, hunter_service_multi_threaded):
    """Test that modifying a nested included file (include within include) causes the hunt to reload."""
    # Create an includes subdirectory
    includes_dir = os.path.join(rules_dir, 'includes')
    os.makedirs(includes_dir, exist_ok=True)
    
    # Create a base included file
    base_include_file = os.path.join(includes_dir, 'base.include.yaml')
    with open(base_include_file, 'w') as fp:
        fp.write("""rule:
  tags:
    - base_tag
  description: Base included description
""")
    
    # Create a middle included file that includes the base
    # Since middle.include.yaml is in the includes/ directory, the path to base.include.yaml
    # should be relative to that directory (just the filename since they're in the same dir)
    middle_include_file = os.path.join(includes_dir, 'middle.include.yaml')
    with open(middle_include_file, 'w') as fp:
        fp.write("""include:
  - base.include.yaml
rule:
  tags:
    - middle_tag
""")
    
    # Create a hunt file that includes the middle file
    hunt_file = os.path.join(rules_dir, 'test_with_nested_include.yaml')
    with open(hunt_file, 'w') as fp:
        fp.write("""include:
  - includes/middle.include.yaml
rule:
  uuid: 9d7f4492-6c3f-5g78-0d2e-1f5g6h7i8j9k
  enabled: yes
  name: test_with_nested_include
  description: Test Hunt With Nested Include
  type: test
  alert_type: test - alert
  frequency: '00:00:10'
  instance_types:
    - unittest
  tags:
    - main_tag
""")
    
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(test_with_nested_include[test]) from', 1)
    
    # Verify the hunt was loaded with all the included tags
    manager = hunter_service_multi_threaded.hunt_managers["test"]
    hunt = next((h for h in manager.hunts if h.name == 'test_with_nested_include'), None)
    assert hunt is not None
    assert 'base_tag' in hunt.tags
    assert 'middle_tag' in hunt.tags
    assert 'main_tag' in hunt.tags
    
    # Modify the base included file (the nested one)
    with open(base_include_file, 'a') as fp:
        fp.write('\n  # modified base included file')
    
    # Wait for the modification to be detected and the hunt to reload
    wait_for_log_count('detected modification to', 1, 5)
    wait_for_log_count('loaded Hunt(test_with_nested_include[test]) from', 2)
    
    # Verify the hunt was reloaded
    hunt_after = next((h for h in manager.hunts if h.name == 'test_with_nested_include'), None)
    assert hunt_after is not None
    
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.system
def test_reload_hunts_on_multiple_included_files(rules_dir, hunter_service_multi_threaded):
    """Test that modifying any of multiple included files causes the hunt to reload."""
    # Create an includes subdirectory
    includes_dir = os.path.join(rules_dir, 'includes')
    os.makedirs(includes_dir, exist_ok=True)
    
    # Create two included files
    include1_file = os.path.join(includes_dir, 'include1.include.yaml')
    with open(include1_file, 'w') as fp:
        fp.write("""rule:
  tags:
    - include1_tag
""")
    
    include2_file = os.path.join(includes_dir, 'include2.include.yaml')
    with open(include2_file, 'w') as fp:
        fp.write("""rule:
  tags:
    - include2_tag
""")
    
    # Create a hunt file that includes both files
    hunt_file = os.path.join(rules_dir, 'test_with_multiple_includes.yaml')
    with open(hunt_file, 'w') as fp:
        fp.write("""include:
  - includes/include1.include.yaml
  - includes/include2.include.yaml
rule:
  uuid: 0e8g5503-7d4g-6h89-1e3f-2g6h7i8j9k0l
  enabled: yes
  name: test_with_multiple_includes
  description: Test Hunt With Multiple Includes
  type: test
  alert_type: test - alert
  frequency: '00:00:10'
  instance_types:
    - unittest
  tags:
    - main_tag
""")
    
    hunter_service_multi_threaded.hunt_managers["test"].update_frequency = 1
    hunter_service_multi_threaded.start()
    wait_for_log_count('loaded Hunt(test_with_multiple_includes[test]) from', 1)
    
    # Verify the hunt was loaded with all the included tags
    manager = hunter_service_multi_threaded.hunt_managers["test"]
    hunt = next((h for h in manager.hunts if h.name == 'test_with_multiple_includes'), None)
    assert hunt is not None
    assert 'include1_tag' in hunt.tags
    assert 'include2_tag' in hunt.tags
    assert 'main_tag' in hunt.tags
    
    # Modify the first included file
    with open(include1_file, 'a') as fp:
        fp.write('\n  # modified include1')
    
    # Wait for the modification to be detected and the hunt to reload
    wait_for_log_count('detected modification to', 1, 5)
    wait_for_log_count('loaded Hunt(test_with_multiple_includes[test]) from', 2)
    
    # Now modify the second included file
    with open(include2_file, 'a') as fp:
        fp.write('\n  # modified include2')
    
    # Wait for another modification to be detected and the hunt to reload again
    wait_for_log_count('detected modification to', 2, 5)
    wait_for_log_count('loaded Hunt(test_with_multiple_includes[test]) from', 3)
    
    # Verify the hunt was reloaded
    hunt_after = next((h for h in manager.hunts if h.name == 'test_with_multiple_includes'), None)
    assert hunt_after is not None
    
    hunter_service_multi_threaded.stop()
    hunter_service_multi_threaded.wait()

@pytest.mark.integration
def test_valid_cron_schedule(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'a') as fp:
        fp.write("""rule:
  uuid: 80c134a8-aa3c-4182-b57e-b159a8874db1
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '*/1 * * * *'
  instance_types:
    - unittest
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
  uuid: 59098a62-67f3-488f-802f-891a34d74b89
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '*/1 * * *'
  instance_types:
    - unittest
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()
    assert len(hunter.hunts) == 0
    assert len(hunter.failed_yaml_files) == 1


@pytest.mark.integration
def test_deleted_failed_hunt_clears_failure_and_triggers_reload(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    failed_yaml_path = os.path.join(rules_dir, 'test_invalid.yaml')
    with open(failed_yaml_path, 'w') as fp:
        fp.write("""rule:
  uuid: 59098a62-67f3-488f-802f-891a34d74b89
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '*/1 * * *'
  instance_types:
    - unittest
  tags:
    - tag1
    - tag2
""")

    hunter = HuntManager(**manager_kwargs)
    hunter.load_hunts_from_config()

    # the invalid cron schedule should cause this yaml to be tracked as a failed file
    assert len(hunter.hunts) == 0
    assert failed_yaml_path in hunter.failed_yaml_files
    assert not hunter.reload_hunts_flag

    # deleting the failed yaml should be treated as resolution:
    # - the failure record is cleared
    # - a reload is triggered
    os.remove(failed_yaml_path)
    hunter.check_hunts()

    assert hunter.reload_hunts_flag
    assert failed_yaml_path not in hunter.failed_yaml_files

@pytest.mark.integration
def test_hunt_suppression(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'a') as fp:
        fp.write("""rule:
  uuid: 1b0c99a0-1d73-4f59-9362-d0c4c0c90b6f
  enabled: yes
  name: unit_test_1
  description: Unit Test Description 1
  type: test
  alert_type: test - alert
  frequency: '00:00:01'
  suppression: '00:01:00'
  instance_types:
    - unittest
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
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    monkeypatch.setattr(get_config().collection, "persistence_dir", "p")
    #monkeypatch.setattr(saq, "CONFIG", { "collection": { "persistence_dir": "p" } })
    hunt = Hunt(manager=MockManager(), config=default_hunt_config(name="test", frequency="00:00:10"))
    #hunt.frequency = timedelta(seconds=10)
    # shoule be ready
    assert hunt.next_execution_time <= local_time()
    assert hunt.ready

@pytest.mark.unit
def test_last_alert_times_persistence(monkeypatch, tmpdir):
    class MockManager:
        @property
        def hunt_type(self):
            return "test"

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    p_dir = data_dir / "p"
    p_dir.mkdir()
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    monkeypatch.setattr(get_config().collection, "persistence_dir", "p")

    hunt = Hunt(manager=MockManager(),
                config=default_hunt_config(name="test_persist", suppression="00:01:00"))
    now = local_time()

    hunt.set_last_alert_time(now, "bob")
    hunt.set_last_alert_time(now, "alice")
    # set_last_alert_time records in memory only; persistence is an explicit flush
    hunt.save_last_alert_times()

    # rehydrate from disk by constructing a fresh Hunt with the same name
    fresh = Hunt(manager=MockManager(),
                 config=default_hunt_config(name="test_persist", suppression="00:01:00"))

    bob_time = fresh.get_last_alert_time("bob")
    alice_time = fresh.get_last_alert_time("alice")

    assert bob_time is not None
    assert alice_time is not None
    assert bob_time.tzinfo is not None
    assert alice_time.tzinfo is not None
    assert bob_time == now
    assert alice_time == now
    assert fresh.get_last_alert_time("never_seen") is None

@pytest.mark.unit
def test_prune_expired_last_alert_times(monkeypatch, tmpdir):
    class MockManager:
        @property
        def hunt_type(self):
            return "test"

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    p_dir = data_dir / "p"
    p_dir.mkdir()
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    monkeypatch.setattr(get_config().collection, "persistence_dir", "p")

    hunt = Hunt(manager=MockManager(),
                config=default_hunt_config(name="test_prune", suppression="00:01:00"))
    now = local_time()

    # one expired entry (10 minutes ago vs 1-minute suppression) and one current entry
    hunt.set_last_alert_time(now - timedelta(minutes=10), "expired")
    hunt.set_last_alert_time(now, "current")

    hunt.prune_expired_last_alert_times()
    # prune mutates in memory only; persistence is an explicit flush
    hunt.save_last_alert_times()

    # rehydrate to confirm the prune was persisted to disk
    fresh = Hunt(manager=MockManager(),
                 config=default_hunt_config(name="test_prune", suppression="00:01:00"))
    assert fresh.get_last_alert_time("expired") is None
    assert fresh.get_last_alert_time("current") is not None

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
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    monkeypatch.setattr(get_config().collection, "persistence_dir", "p")
    #monkeypatch.setattr(saq, "CONFIG", { "collection": { "persistence_dir": "p" } })
    hunt = Hunt(manager=MockManager(), config=default_hunt_config(name="test", frequency="*/10 * * * *"))
    # shoule be ready
    assert hunt.next_execution_time <= local_time()
    assert hunt.ready

@pytest.mark.unit
def test_next_execution_time_cron_with_previous_execution(monkeypatch, tmpdir):
    class MockManager:
        @property
        def hunt_type(self):
            return "test"

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    p_dir = data_dir / "p"
    p_dir.mkdir()
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    monkeypatch.setattr(get_config().collection, "persistence_dir", "p")
    hunt = Hunt(manager=MockManager(), config=default_hunt_config(name="test", frequency="*/10 * * * *"))

    # set a previous execution time
    previous_execution = local_time() - timedelta(minutes=15)
    hunt.last_executed_time = previous_execution

    # next execution time should be calculated from the cron schedule based on last execution
    next_exec = hunt.next_execution_time
    assert next_exec is not None
    assert next_exec > previous_execution
    # should be approximately 10 minutes after the previous execution
    # allowing for some variance due to cron schedule alignment
    assert next_exec <= local_time() + timedelta(minutes=10)

@pytest.mark.integration
def test_load_hunt_with_instance_types(rules_dir, manager_kwargs):
    shutil.rmtree(rules_dir)
    os.mkdir(rules_dir)
    with open(os.path.join(rules_dir, 'test_1.yaml'), 'w') as fp:
        fp.write("""rule:
  uuid: 557a5cc4-5d0e-4142-8f47-52c369ade9da
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
  uuid: 7b6aea50-cf49-4985-b600-79fb90264fcb
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
    # when instance_types is empty, hunt should not be valid (instance type must be specified)
    monkeypatch.setattr(get_config().global_settings, "instance_type", "production")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter, instance_types=[])

    assert not hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_is_valid_instance_type_matching(manager_kwargs, monkeypatch):
    # hunt with instance_types=['production'] should be valid for production instance
    monkeypatch.setattr(get_config().global_settings, "instance_type", "production")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter, instance_types=['production', 'development'])

    assert hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_is_valid_instance_type_case_insensitive(manager_kwargs, monkeypatch):
    # instance type matching should be case insensitive
    monkeypatch.setattr(get_config().global_settings, "instance_type", "Production")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter, instance_types=['PRODUCTION', 'development'])

    assert hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_is_valid_instance_type_non_matching(manager_kwargs, monkeypatch):
    # hunt with instance_types=['production'] should not be valid for development instance
    monkeypatch.setattr(get_config().global_settings, "instance_type", "development")

    hunter = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=hunter, instance_types=['production'])

    assert not hunter.is_valid_instance_type(hunt)

@pytest.mark.integration
def test_hunt_execution_skips_invalid_instance_type(manager_kwargs, monkeypatch):
    # hunts with invalid instance types should not execute
    monkeypatch.setattr(get_config().global_settings, "instance_type", "production")

    hunter = HuntManager(**manager_kwargs)

    # add a hunt valid for production
    valid_hunt = default_hunt(manager=hunter, name='valid_hunt', instance_types=['production'])
    hunter.add_hunt(valid_hunt)

    # add a hunt valid for development only
    invalid_hunt = default_hunt(manager=hunter, name='invalid_hunt', instance_types=['development'])
    hunter.add_hunt(invalid_hunt)

    # add a hunt with empty instance types (should also be invalid now that instance types must be specified)
    empty_instance_hunt = default_hunt(manager=hunter, name='empty_instance_hunt', instance_types=[])
    hunter.add_hunt(empty_instance_hunt)

    # execute all hunts
    hunter.execute()
    hunter.manager_control_event.set()
    hunter.wait_control_event.set()
    hunter.wait()

    # only valid_hunt should have executed
    assert valid_hunt.executed

    # invalid_hunt and empty_instance_hunt should not have executed
    assert not invalid_hunt.executed
    assert not empty_instance_hunt.executed

class _RecordingQueue(Queue):
    """records the transaction id in effect each time something is queued"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.transaction_ids = []

    def put(self, item, *args, **kwargs):
        self.transaction_ids.append(get_transaction_id())
        super().put(item, *args, **kwargs)

@pytest.mark.integration
def test_execute_threaded_hunt_queues_under_hunt_transaction_id(manager_kwargs):
    """the submissions a hunt produced are queued under that hunt run's transaction id

    execute_with_lock() exits its transaction id context before the manager queues
    anything, so the manager has to re-enter it explicitly"""
    manager_kwargs["submission_queue"] = _RecordingQueue()
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=manager)
    # normally set by execute_hunt() before it hands the hunt to the execution thread
    hunt.semaphore = None

    manager.execute_threaded_hunt(hunt)

    assert hunt.last_transaction_id is not None
    assert hunt.last_transaction_id != DEFAULT_TRANSACTION_ID
    assert manager.submission_queue.transaction_ids == [hunt.last_transaction_id]

@pytest.mark.integration
def test_execute_threaded_hunt_stamps_queued_time(manager_kwargs):
    """each queued submission is stamped so the collector can report how long it waited"""
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=manager)
    # normally set by execute_hunt() before it hands the hunt to the execution thread
    hunt.semaphore = None

    manager.execute_threaded_hunt(hunt)

    submission = manager.submission_queue.get_nowait()
    assert submission.queued_time is not None
    assert submission.queue_age >= 0

    assert log_count("queued 1 submissions for hunt") == 1
    assert log_count("post-processed 1 submissions for hunt") == 1

class _GroupedTestHunt(TestHunt):
    """a grouped hunt that emits one submission per group value

    the base Hunt.group_by property always returns None and group_by is a QueryHuntConfig
    field, so grouping has to be introduced by a subclass rather than by config"""
    __test__ = False

    def __init__(self, *args, group_values=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.group_values = group_values or []

    @property
    def group_by(self):
        return "src"

    def execute(self):
        self.executed = True
        submissions = []
        for group_value in self.group_values:
            root_uuid = str(uuid4())
            root = RootAnalysis(
                uuid=root_uuid,
                storage_dir=get_storage_dir(root_uuid),
                desc='test',
                analysis_mode=ANALYSIS_MODE_CORRELATION,
                tool='test_tool',
                tool_instance='test_tool_instance',
                alert_type='test_type')
            root.initialize_storage()
            submission = Submission(root)
            submission.group_value = group_value
            submissions.append(submission)

        return submissions

@pytest.mark.integration
def test_execute_threaded_hunt_skips_suppression_tracking_when_not_configured(manager_kwargs):
    """a grouped hunt with no suppression must not write last_alert_times

    the only reader of last_alert_times is is_group_suppressed(), which returns False without
    reading them when suppression is unset - so recording them is pure cost. each write pickles
    the entire (never pruned) dict, which starves the collector and delivery threads sharing
    this process"""
    manager = HuntManager(**manager_kwargs)
    hunt = _GroupedTestHunt(
        manager=manager,
        config=default_hunt_config(name="test_no_suppression"),
        group_values=["alice", "bob", "charlie"])
    # normally set by execute_hunt() before it hands the hunt to the execution thread
    hunt.semaphore = None

    assert hunt.suppression is None

    manager.execute_threaded_hunt(hunt)

    # all three submissions still make it to the queue
    assert manager.submission_queue.qsize() == 3

    # but nothing was recorded, in memory or on disk
    assert hunt.last_alert_times == {}
    assert read_persistence_data(hunt.type, hunt.name, "last_alert_times") is None
    assert log_count("suppression tracking disabled") == 1

@pytest.mark.integration
def test_execute_threaded_hunt_records_suppression_state_when_configured(manager_kwargs):
    """a grouped hunt that does configure suppression still records per-group times"""
    manager = HuntManager(**manager_kwargs)
    hunt = _GroupedTestHunt(
        manager=manager,
        config=default_hunt_config(name="test_with_suppression", suppression="00:01:00"),
        group_values=["alice", "bob"])
    hunt.semaphore = None

    assert hunt.suppression is not None

    manager.execute_threaded_hunt(hunt)

    assert hunt.get_last_alert_time("alice") is not None
    assert hunt.get_last_alert_time("bob") is not None

    # and it was persisted
    persisted = read_persistence_data(hunt.type, hunt.name, "last_alert_times")
    assert persisted is not None
    assert set(persisted.keys()) == {"alice", "bob"}
    assert log_count("suppression tracking enabled") == 1

@pytest.mark.integration
def test_execute_threaded_hunt_still_records_ungrouped_last_alert_time(manager_kwargs):
    """the ungrouped branch is untouched - it writes once per run, not once per submission"""
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=manager, name="test_ungrouped")
    hunt.semaphore = None

    assert hunt.group_by is None

    manager.execute_threaded_hunt(hunt)

    assert hunt.last_alert_time is not None

def _count_persistence_writes(monkeypatch, value_name="last_alert_times"):
    """patches write_persistence_data to count writes of a given value name

    returns a single-element list holding the count so callers can read it after the fact"""
    import saq.collectors.hunter.base_hunter as base_hunter_module

    count = [0]
    real_write = base_hunter_module.write_persistence_data

    def _counting_write(hunt_type, hunt_name, name, value):
        if name == value_name:
            count[0] += 1
        return real_write(hunt_type, hunt_name, name, value)

    monkeypatch.setattr(base_hunter_module, "write_persistence_data", _counting_write)
    return count

@pytest.mark.integration
def test_execute_threaded_hunt_writes_last_alert_times_once_per_run(manager_kwargs, monkeypatch):
    """a suppressed grouped hunt writes the persistence file exactly once, not once per group

    this is the assertion that encodes the fix: set_last_alert_time used to pickle the whole
    dict on every call, making a run O(groups^2)"""
    writes = _count_persistence_writes(monkeypatch)

    group_values = [f"group{i}" for i in range(20)]
    manager = HuntManager(**manager_kwargs)
    hunt = _GroupedTestHunt(
        manager=manager,
        config=default_hunt_config(name="test_single_write", suppression="00:01:00"),
        group_values=group_values)
    hunt.semaphore = None

    manager.execute_threaded_hunt(hunt)

    # every group was recorded...
    for group_value in group_values:
        assert hunt.get_last_alert_time(group_value) is not None

    # ...in exactly one disk write (previously this would have been 20)
    assert writes[0] == 1

    # and it round trips
    persisted = read_persistence_data(hunt.type, hunt.name, "last_alert_times")
    assert set(persisted.keys()) == set(group_values)

@pytest.mark.unit
def test_set_last_alert_time_does_not_write_to_disk(monkeypatch, tmpdir):
    """set_last_alert_time records in memory only - the write is an explicit flush"""
    class MockManager:
        @property
        def hunt_type(self):
            return "test"

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    p_dir = data_dir / "p"
    p_dir.mkdir()
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    monkeypatch.setattr(get_config().collection, "persistence_dir", "p")

    writes = _count_persistence_writes(monkeypatch)

    hunt = Hunt(manager=MockManager(),
                config=default_hunt_config(name="test_no_write", suppression="00:01:00"))
    now = local_time()

    hunt.set_last_alert_time(now, "alice")

    # readable in memory, but nothing on disk yet
    assert hunt.get_last_alert_time("alice") == now
    assert writes[0] == 0
    assert read_persistence_data(hunt.type, hunt.name, "last_alert_times") is None

    hunt.save_last_alert_times()
    assert writes[0] == 1

    # a second flush with nothing changed is a no-op
    hunt.save_last_alert_times()
    assert writes[0] == 1

@pytest.mark.unit
def test_prune_expired_last_alert_times_preserves_concurrent_inserts(monkeypatch, tmpdir):
    """pruning removes expired keys in place rather than assigning a rebuilt dict

    a hunt can be re-dispatched while the previous run is still post-processing, so a rebuilt
    dict would silently drop entries the other run inserted after the snapshot was taken"""
    class MockManager:
        @property
        def hunt_type(self):
            return "test"

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    p_dir = data_dir / "p"
    p_dir.mkdir()
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    monkeypatch.setattr(get_config().collection, "persistence_dir", "p")

    hunt = Hunt(manager=MockManager(),
                config=default_hunt_config(name="test_prune_concurrent", suppression="00:01:00"))
    now = local_time()

    hunt.set_last_alert_time(now - timedelta(minutes=10), "expired")
    hunt.set_last_alert_time(now, "current")

    # hold the same dict object a concurrent run would be mutating
    shared = hunt.last_alert_times
    hunt.prune_expired_last_alert_times()
    # simulate the other run inserting after the prune decided what to drop
    hunt.set_last_alert_time(now, "inserted_concurrently")

    assert hunt.last_alert_times is shared, "prune must not replace the dict object"
    assert hunt.get_last_alert_time("expired") is None
    assert hunt.get_last_alert_time("current") is not None
    assert hunt.get_last_alert_time("inserted_concurrently") is not None

@pytest.mark.integration
def test_execute_threaded_hunt_discards_suppression_state_when_unsuppressed(manager_kwargs):
    """a grouped hunt with no suppression drops any state a previous version persisted"""
    manager = HuntManager(**manager_kwargs)

    # stand in for what the old code left on disk
    seeded = _GroupedTestHunt(
        manager=manager,
        config=default_hunt_config(name="test_discard", suppression="00:01:00"),
        group_values=[])
    seeded.set_last_alert_time(local_time(), "stale")
    seeded.save_last_alert_times()
    assert read_persistence_data(seeded.type, seeded.name, "last_alert_times") is not None

    # same hunt name, but suppression is no longer configured
    hunt = _GroupedTestHunt(
        manager=manager,
        config=default_hunt_config(name="test_discard"),
        group_values=["alice"])
    hunt.semaphore = None

    manager.execute_threaded_hunt(hunt)

    assert hunt.last_alert_times == {}
    assert read_persistence_data(hunt.type, hunt.name, "last_alert_times") is None

@pytest.mark.integration
def test_execute_threaded_hunt_does_not_write_when_nothing_changed(manager_kwargs, monkeypatch):
    """a run that produces no submissions must not touch the persistence file"""
    writes = _count_persistence_writes(monkeypatch)

    manager = HuntManager(**manager_kwargs)
    hunt = _GroupedTestHunt(
        manager=manager,
        config=default_hunt_config(name="test_no_submissions", suppression="00:01:00"),
        group_values=[])
    hunt.semaphore = None

    manager.execute_threaded_hunt(hunt)

    assert writes[0] == 0

@pytest.mark.integration
def test_execute_threaded_hunt_survives_execution_failure(manager_kwargs):
    """a hunt that raises does not take the execution thread down with it"""
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=manager)
    hunt.semaphore = None

    def _boom(*args, **kwargs):
        raise RuntimeError("nope")

    hunt.execute_with_lock = _boom
    manager.execute_threaded_hunt(hunt)

    assert manager.submission_queue.empty()

@pytest.mark.integration
def test_failed_hunt_backs_off(manager_kwargs):
    """A hunt that fails must not become immediately ready again.

    last_executed_time used to be recorded only on success, so a failing hunt stayed `ready`
    and the manager re-ran it roughly once a second. A brief data source outage then produced
    thousands of failures and hammered the source with new queries while it was already
    unhealthy.
    """
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=manager, frequency='00:10')
    hunt.semaphore = None

    def _boom():
        raise RemoteApiError(401, "transient upstream failure")

    hunt.execute = _boom
    assert hunt.ready is True

    hunt.execute_with_lock(ExecutionMode.SINGLE_SHOT)

    # the failed attempt still counts as an execution, so the normal frequency now applies
    assert hunt.last_executed_time is not None
    assert hunt.ready is False


@pytest.mark.integration
def test_failed_full_coverage_hunt_does_not_advance_last_end_time(manager_kwargs):
    """Backing off must not skip the time range the failed run was supposed to cover."""
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(manager=manager, frequency='00:10')
    hunt.semaphore = None

    def _boom():
        raise RemoteApiError(401, "transient upstream failure")

    hunt.execute = _boom
    hunt.execute_with_lock(ExecutionMode.SINGLE_SHOT)

    assert hunt.ready is False
    # no coverage was recorded for a window we never actually searched
    assert read_persistence_data(hunt.type, hunt.name, 'last_end_time') is None
