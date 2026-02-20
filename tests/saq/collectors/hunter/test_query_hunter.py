import configparser
import logging
import os
import shutil
from datetime import datetime, timedelta
from queue import Queue

import pytest
import yaml

import saq.collectors.hunter.base_hunter as hunter_base
import saq.collectors.hunter.query_hunter as query_hunter_module
import saq.util.time as saq_time
from saq.collectors.hunter import HunterService, HuntManager, read_persistence_data
from saq.collectors.hunter.query_hunter import (
    ObservableMapping,
    QueryHunt,
    QueryHuntConfig,
    RelationshipMapping,
    RelationshipMappingTarget,
)
from saq.configuration.config import get_config
from saq.configuration.schema import HuntTypeConfig
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    F_COMMAND_LINE,
    F_HOSTNAME,
    F_IPV4,
    F_SIGNATURE_ID,
    R_EXECUTED_ON,
    R_RELATED_TO,
)
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.observables.mapping import FieldsMode
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

def default_hunt(
    # base hunter
    uuid="cb7ec70f-0e81-4d84-b8bc-e5a3907dd4f7",
    name="test_hunt",
    type="test_query",
    enabled=True,
    description="Test Hunt",
    alert_type="test - query",
    frequency="00:10",
    tags=[ "test_tag" ],
    instance_types=["unittest"],

    # query hunter
    time_range="00:10",
    max_time_range="24:00:00",
    full_coverage=True,
    use_index_time=True,
    query="index=test sourcetype=test test_string",
    group_by="field1",
    description_field=None,
    **kwargs):

    config = QueryHuntConfig(
        uuid=uuid,
        name=name,
        type=type,
        enabled=enabled,
        description=description,
        alert_type=alert_type,
        frequency=frequency,
        tags=tags,
        instance_types=instance_types,
        query=query,
        time_range=time_range,
        max_time_range=max_time_range,
        full_coverage=full_coverage,
        use_index_time=use_index_time,
        group_by=group_by,
        description_field=description_field,
        **kwargs
    )

    return TestQueryHunt(config=config)

@pytest.fixture
def manager_kwargs(rules_dir):
    return { 'submission_queue': Queue(),
             'hunt_type': 'test_query',
             'rule_dirs': [ rules_dir ],
             'hunt_cls': TestQueryHunt,
             'concurrency_limit': 1,
             'persistence_dir': os.path.join(get_data_dir(), get_config().collection.persistence_dir),
             'update_frequency': 60 ,
             'config': {}}

@pytest.fixture
def rules_dir(tmpdir, datadir) -> str:
    temp_rules_dir = datadir / "test_rules"
    shutil.copytree("hunts/test/generic", temp_rules_dir)
    return str(temp_rules_dir)

@pytest.fixture(autouse=True, scope="function")
def setup(rules_dir):
    get_config().add_hunt_type_config("test_query",
        HuntTypeConfig(
            name='test_query',
            python_module='tests.saq.collectors.hunter.test_query_hunter',
            python_class='TestQueryHunt',
            rule_dirs=[rules_dir],
            update_frequency=60
        )
    )

    test_yaml_path = os.path.join(rules_dir, 'test_1.yaml')
    with open(test_yaml_path, 'w') as fp:
        yaml.dump({
            'rule': {
                'uuid': 'c36e8ddd-aa3e-46be-a80e-d6df94d9aade',
                'enabled': 'yes',
                'name': 'query_test_1',
                'description': 'Query Test Description 1',
                'type': 'test_query',
                'alert_type': 'test - query',
                'frequency': '00:01:00',
                'tags': ['tag1', 'tag2'],
                'time_range': '00:01:00',
                'max_time_range': '01:00:00',
                'offset': '00:05:00',
                'full_coverage': 'yes',
                'group_by': 'field1',
                'search': f'{rules_dir}/test_1.query',
                'use_index_time': 'yes',
                'instance_types': ['unittest']
            },
            'observable_mapping': [
                {
                    'fields': ['src_ip'],
                    'type': 'ipv4',
                    'time': True,
                },
                {
                    'fields': ['dst_ip'],
                    'type': 'ipv4',
                    'time': True,
                },
            ],
        }, fp, default_flow_style=False)

    test_query_path = os.path.join(rules_dir, 'test_1.query')
    with open(test_query_path, 'w') as fp:
        fp.write('Test query.')

@pytest.mark.integration
def test_load_hunt_yaml(manager_kwargs):
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    hunt = manager.hunts[0]
    assert hunt.enabled
    assert hunt.uuid == 'c36e8ddd-aa3e-46be-a80e-d6df94d9aade'
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
    assert hunt.observable_mapping == []
    #assert hunt.temporal_fields == { 'src_ip': True, 'dst_ip': True }

@pytest.mark.integration
def test_load_query_inline(rules_dir, manager_kwargs):
    test_yaml_path = os.path.join(rules_dir, 'test_1.yaml')
    with open(test_yaml_path, 'w') as fp:
        yaml.dump({
            'rule': {
                'uuid': 'af7ab6f2-008b-44d1-8a70-339d61186ad2',
                'enabled': 'yes',
                'name': 'query_test_1',
                'description': 'Query Test Description 1',
                'type': 'test_query',
                'alert_type': 'test - query',
                'frequency': '00:01:00',
                'tags': ['tag1', 'tag2'],
                'time_range': '00:01:00',
                'max_time_range': '01:00:00',
                'offset': '00:05:00',
                'full_coverage': 'yes',
                'group_by': 'field1',
                'query': 'Test query.',
                'use_index_time': 'yes',
                'instance_types': ['unittest']
            },
            'observable_mapping': {
                'src_ip': 'ipv4',
                'dst_ip': 'ipv4'
            },
            'temporal_fields': {
                'src_ip': True,
                'dst_ip': True
            },
            'directives': {}
        }, fp, default_flow_style=False)
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    hunt = manager.hunts[0]
    assert hunt.enabled
    assert hunt.query == 'Test query.'

@pytest.mark.integration
def test_load_multi_line_query_inline(rules_dir, manager_kwargs):
    test_yaml_path = os.path.join(rules_dir, 'test_1.yaml')
    with open(test_yaml_path, 'w') as fp:
        yaml.dump({
            'rule': {
                'uuid': '072e8b57-e296-4b5c-951a-2e43c359748a',
                'enabled': 'yes',
                'name': 'query_test_1',
                'description': 'Query Test Description 1',
                'type': 'test_query',
                'alert_type': 'test - query',
                'frequency': '00:01:00',
                'tags': ['tag1', 'tag2'],
                'time_range': '00:01:00',
                'max_time_range': '01:00:00',
                'offset': '00:05:00',
                'full_coverage': 'yes',
                'group_by': 'field1',
                'query': 'This is a multi line query.\nHow about that?',
                'use_index_time': 'yes',
                'instance_types': ['unittest']
            },
            'observable_mapping': [
                {
                    'fields': ['src_ip'],
                    'type': 'ipv4',
                    'time': True,
                },
                {
                    'fields': ['dst_ip'],
                    'type': 'ipv4',
                    'time': True,
                },
            ],
        }, fp, default_flow_style=False)
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    hunt = manager.hunts[0]
    assert hunt.enabled
    assert hunt.query == 'This is a multi line query.\nHow about that?'

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
    assert log_count('loading hunt from') >= 2
    assert log_count('loaded Hunt(query_test_1[test_query])') == 1

    # wait for the hunt to execute
    wait_for_log_count('executing query', 1)

    # we should have persistence data for both the last_executed_time and last_end_time fields
    assert isinstance(read_persistence_data('test_query', 'query_test_1', 'last_executed_time'), datetime) # last_executed_time
    assert isinstance(read_persistence_data('test_query', 'query_test_1', 'last_end_time'), datetime) # last_end_time

    hunter_service.stop()
    hunter_service.wait()

@pytest.fixture
def full_coverage_hunt(manager_kwargs, monkeypatch):
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(time_range='01:00:00', frequency='01:00:00')
    hunt.manager = manager
    manager.add_hunt(hunt)

    state = {"now": saq_time.local_time()}

    def apply_time_patch():
        monkeypatch.setattr(query_hunter_module, "local_time", lambda: state["now"])
        monkeypatch.setattr(hunter_base, "local_time", lambda: state["now"])

    def set_now(new_now=None):
        if new_now is None:
            new_now = saq_time.local_time()
        state["now"] = new_now
        apply_time_patch()
        return state["now"]

    set_now(state["now"])
    return hunt, set_now

@pytest.mark.integration
def test_full_coverage_ready_states(full_coverage_hunt):
    hunt, set_now = full_coverage_hunt

    current = set_now()
    assert hunt.ready

    current = set_now()
    hunt.last_executed_time = current - timedelta(minutes=5)
    assert not hunt.ready

    current = set_now()
    hunt.last_executed_time = current - timedelta(minutes=65)
    assert hunt.ready

@pytest.mark.integration
def test_full_coverage_respects_last_end_time(full_coverage_hunt):
    hunt, set_now = full_coverage_hunt

    current = set_now()
    hunt.last_executed_time = current - timedelta(hours=3)
    hunt.last_end_time = current - timedelta(hours=2)

    assert hunt.ready
    assert hunt.start_time == hunt.last_end_time
    assert hunt.end_time == hunt.last_end_time + hunt.time_range

@pytest.mark.integration
def test_full_coverage_catch_up_with_max_range(full_coverage_hunt):
    hunt, set_now = full_coverage_hunt

    hunt.config.max_time_range = '02:00:00'
    baseline = set_now()
    current = set_now(baseline + timedelta(seconds=1))
    hunt.last_executed_time = current - timedelta(hours=3)
    hunt.last_end_time = current - timedelta(hours=2, seconds=1)

    assert hunt.end_time - hunt.start_time >= hunt.max_time_range

@pytest.mark.integration
def test_full_coverage_disabled_falls_back_to_frequency(full_coverage_hunt):
    hunt, set_now = full_coverage_hunt

    current = set_now()
    hunt.config.full_coverage = False
    hunt.last_executed_time = current - timedelta(hours=3)
    hunt.last_end_time = current - timedelta(hours=2)

    assert hunt.ready
    assert hunt.start_time == current - hunt.time_range

@pytest.mark.integration
def test_offset(manager_kwargs):
    manager = HuntManager(**manager_kwargs)
    hunt = default_hunt(time_range='01:00:00', frequency='01:00:00', offset='00:30:00')
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
    # there's another file in here that is not valid for a query hunter lol
    assert len(manager.failed_yaml_files) == 2

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

class MockManager:
    @property
    def hunt_type(self):
        return "test"

@pytest.mark.unit
def test_query_hunter_end_time(monkeypatch, tmpdir):

    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    data_dir = tmpdir / "data"
    data_dir.mkdir()
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    mock_config = configparser.ConfigParser()
    mock_config.read_string("""[collection]
                            persistence_dir = p
                            """)
    hunt = default_hunt(manager=MockManager(), name="test")
    assert hunt.end_time

    # full coverage end time
    hunt.config.full_coverage = True
    hunt.last_end_time = mock_local_time() - timedelta(hours=1)
    hunt.config.time_range = '01:00:00'
    assert hunt.end_time == hunt.last_end_time + hunt.time_range

    # full coverage, we're behind by one hour and max_time_range is not set
    hunt.config.max_time_range = None
    hunt.last_end_time = mock_local_time() - timedelta(hours=2)
    assert hunt.end_time == hunt.last_end_time + timedelta(hours=1) # can only go in increments of time_range

    # full coverage, we're behind by one hour and max_time_range is set
    hunt.last_end_time = mock_local_time() - timedelta(hours=3)
    hunt.config.max_time_range = '02:00:00'
    assert hunt.end_time == hunt.last_end_time + create_timedelta('02:00:00') # can go up to max time range

    # but no more than that at a time
    hunt.config.max_time_range = '08:00:00'
    hunt.last_end_time = mock_local_time() - timedelta(hours=9)
    assert hunt.end_time == hunt.last_end_time + timedelta(hours=8) # can go up to max time range

@pytest.mark.unit
def test_query_hunter_ready(monkeypatch, tmpdir):
    data_dir = tmpdir / "data"
    data_dir.mkdir()
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(data_dir))
    mock_config = configparser.ConfigParser()
    mock_config.read_string("""[collection]
                            persistence_dir = p
                            """)
    #monkeypatch.setattr(saq, "CONFIG", { "collection": { "persistence_dir": "p" } })
    hunt = default_hunt(manager=MockManager(), name="test")
    #hunt = QueryHunt(manager=MockManager(), config=default_query_hunt_config(name="test"))

    # we just ran and our frequency is sent to an hour
    hunt.last_executed_time = mock_local_time()
    hunt.config.frequency = '01:00:00'
    assert not hunt.ready

    # we ran an hour ago and frequency is set to an hour
    hunt.last_executed_time = mock_local_time() - timedelta(hours=1)
    hunt.config.frequency = '01:00:00'
    assert hunt.ready

    # full coverage testing
    # we ran 2 hours ago, range is set to an hour and frequency is set to an hour
    hunt.config.full_coverage = True
    hunt.last_executed_time = mock_local_time() - timedelta(hours=2)
    hunt.config.frequency = '01:00:00'
    assert hunt.ready

    # this logic is no longer supported
    #hunt.last_executed_time = mock_local_time()
    #hunt.last_end_time = mock_local_time() - timedelta(hours=2)
    #hunt.frequency = timedelta(hours=1)
    #hunt.time_range = timedelta(hours=1)
    #assert hunt.ready

@pytest.mark.unit
def test_process_query_results(monkeypatch):
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(manager=MockManager(),
        name="test",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        alert_type="test-type",
        queue="test-queue",
        description="test instructions",
        playbook_url="http://playbook",
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ipv4")
        ]
    )

    assert hunt.process_query_results(None) is None
    assert not hunt.process_query_results([])
    submissions = hunt.process_query_results([{}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]
    assert submission.root.description == "test (1 event)"
    assert submission.root.analysis_mode == hunt.analysis_mode
    assert submission.root.tool == f"hunter-{hunt.type}"
    assert submission.root.tool_instance == "localhost"
    assert submission.root.alert_type == hunt.alert_type
    assert submission.root.event_time == mock_local_time()
    assert isinstance(submission.root.details, dict)
    assert "events" in submission.root.details
    assert isinstance(submission.root.details["events"], list)
    assert len(submission.root.details["events"]) == 1
    assert submission.root.details["events"][0] == {}
    assert len(submission.root.observables) == 1 # only F_SIGNATURE_ID
    signature_id_observable = next((o for o in submission.root.observables if o.type == F_SIGNATURE_ID), None)
    assert signature_id_observable.value == hunt.uuid
    assert submission.root.tags == ["test_tag"]
    #assert submission.root.files == []
    assert submission.root.queue == hunt.queue
    #assert submission.root.instructions == hunt.description
    assert submission.root.extensions == { "playbook_url": hunt.playbook_url }

    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]
    assert len(submission.root.observables) == 2
    for observable in submission.root.observables:
        if observable.type == F_SIGNATURE_ID:
            assert observable.value == hunt.uuid
        elif observable.type == F_IPV4:
            assert observable.value == "1.2.3.4"
            assert not observable.volatile
        else:
            assert False, f"unexpected observable type: {observable.type}"

        assert not observable.time
        assert not observable.tags
        assert not observable.directives

    # test volatile observable
    hunt.config.observable_mapping = [
        ObservableMapping(fields=["src"], type="ipv4", volatile=True)
    ]
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]
    ipv4_observable = next((o for o in submission.root.observables if o.type == F_IPV4), None)
    assert ipv4_observable is not None
    assert ipv4_observable.volatile

    hunt.config.group_by = "src"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "1.2.3.5"},
    ])
    assert submissions
    assert len(submissions) == 2
    for submission in submissions:
        assert len(submission.root.observables) == 2
        assert submission.root.description.endswith(": 1.2.3.4 (1 event)") or submission.root.description.endswith(": 1.2.3.5 (1 event)")

    hunt.config.group_by = "dst"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "1.2.3.5"},
    ])
    assert submissions
    assert len(submissions) == 2
    for submission in submissions:
        assert len(submission.root.observables) == 2
        assert submission.root.description == "test (1 event)"

    hunt.config.group_by = "ALL"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "1.2.3.5"},
    ])
    assert submissions
    assert len(submissions) == 1
    for submission in submissions:
        assert len(submission.root.observables) == 3
        assert submission.root.description == "test (2 events)"


@pytest.mark.unit
def test_process_query_results_file_observable(monkeypatch, tmpdir):
    """test mapping fields to F_FILE type observables"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    # set up temp directory for file observables
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt"
            )
        ]
    )

    # test with string content - should be encoded to bytes
    submissions = hunt.process_query_results([{"file_content": "hello world"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # should have F_SIGNATURE_ID observable plus the file observable
    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]
    assert file_obs.file_name == "test_file.txt"

    # verify file was created with correct content
    with open(file_obs.full_path, "rb") as f:
        assert f.read() == b"hello world"


@pytest.mark.unit
def test_process_query_results_file_observable_with_interpolation(monkeypatch, tmpdir):
    """test F_FILE observable with interpolated file name"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content", "filename"],
                type=F_FILE,
                file_name="${filename}"
            )
        ]
    )

    submissions = hunt.process_query_results([{
        "file_content": "test data",
        "filename": "dynamic_file.bin"
    }])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]
    assert file_obs.file_name == "dynamic_file.bin"


@pytest.mark.unit
def test_process_query_results_file_observable_with_base64_decoder(monkeypatch, tmpdir):
    """test F_FILE observable with base64 decoder"""
    import base64

    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.decoder import DecoderType
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["encoded_content"],
                type=F_FILE,
                file_name="decoded_file.txt",
                file_decoder=DecoderType.BASE64
            )
        ]
    )

    original_content = b"decoded content from base64"
    encoded_content = base64.b64encode(original_content).decode("utf-8")

    submissions = hunt.process_query_results([{"encoded_content": encoded_content}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    with open(file_obs.full_path, "rb") as f:
        assert f.read() == original_content


@pytest.mark.unit
def test_process_query_results_file_observable_with_ascii_hex_decoder(monkeypatch, tmpdir):
    """test F_FILE observable with ascii hex decoder"""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.decoder import DecoderType
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["hex_content"],
                type=F_FILE,
                file_name="hex_decoded.bin",
                file_decoder=DecoderType.ASCII_HEX
            )
        ]
    )

    original_content = b"hex decoded"
    hex_content = original_content.hex()

    submissions = hunt.process_query_results([{"hex_content": hex_content}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    with open(file_obs.full_path, "rb") as f:
        assert f.read() == original_content


@pytest.mark.unit
def test_process_query_results_file_observable_with_grouping(monkeypatch, tmpdir):
    """test F_FILE observable with grouped events"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by="group_field",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="grouped_file.txt"
            )
        ]
    )

    submissions = hunt.process_query_results([
        {"file_content": "content1", "group_field": "group_a"},
        {"file_content": "content2", "group_field": "group_a"},
        {"file_content": "content3", "group_field": "group_b"},
    ])
    assert submissions
    assert len(submissions) == 2

    # find submission for each group
    group_a_submission = next((s for s in submissions if "group_a" in s.root.description), None)
    group_b_submission = next((s for s in submissions if "group_b" in s.root.description), None)

    assert group_a_submission is not None
    assert group_b_submission is not None

    # group_a should have 2 file observables
    group_a_files = [o for o in group_a_submission.root.observables if o.type == F_FILE]
    assert len(group_a_files) == 2

    # group_b should have 1 file observable
    group_b_files = [o for o in group_b_submission.root.observables if o.type == F_FILE]
    assert len(group_b_files) == 1


@pytest.mark.unit
def test_process_query_results_file_observable_missing_field(monkeypatch, tmpdir):
    """test F_FILE observable when required field is missing"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt"
            )
        ]
    )

    # event is missing the file_content field
    submissions = hunt.process_query_results([{"other_field": "value"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # should only have F_SIGNATURE_ID, no file observable
    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 0


@pytest.mark.unit
def test_process_query_results_file_observable_empty_content(monkeypatch, tmpdir):
    """test F_FILE observable when content is empty"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt"
            )
        ]
    )

    # event has empty file content
    submissions = hunt.process_query_results([{"file_content": ""}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # should only have F_SIGNATURE_ID, no file observable (empty content is skipped)
    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 0


@pytest.mark.unit
def test_process_query_results_file_observable_with_directives(monkeypatch, tmpdir):
    """test F_FILE observable with directives"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import DIRECTIVE_SANDBOX, F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt",
                directives=[DIRECTIVE_SANDBOX, "custom_directive"]
            )
        ]
    )

    submissions = hunt.process_query_results([{"file_content": "malicious content"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    assert DIRECTIVE_SANDBOX in file_obs.directives
    assert "custom_directive" in file_obs.directives


@pytest.mark.unit
def test_process_query_results_file_observable_with_tags(monkeypatch, tmpdir):
    """test F_FILE observable with tags"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt",
                tags=["suspicious", "needs_review"]
            )
        ]
    )

    submissions = hunt.process_query_results([{"file_content": "tagged content"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    assert "suspicious" in file_obs.tags
    assert "needs_review" in file_obs.tags


@pytest.mark.unit
def test_process_query_results_file_observable_with_volatile(monkeypatch, tmpdir):
    """test F_FILE observable with volatile property set to False"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    # test with volatile=False (the default)
    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt",
                volatile=False
            )
        ]
    )

    submissions = hunt.process_query_results([{"file_content": "non-volatile content"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    # the file observable should NOT be volatile when volatile=False in mapping
    assert not file_obs.volatile


@pytest.mark.unit
def test_process_query_results_file_observable_with_volatile_true(monkeypatch, tmpdir):
    """test F_FILE observable with volatile property set to True"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt",
                volatile=True
            )
        ]
    )

    submissions = hunt.process_query_results([{"file_content": "volatile content"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    assert file_obs.volatile


@pytest.mark.unit
def test_process_query_results_file_observable_with_interpolated_tags(monkeypatch, tmpdir):
    """test F_FILE observable with interpolated tags from event fields"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content", "source_system"],
                type=F_FILE,
                file_name="test_file.txt",
                tags=["source:${source_system}", "static_tag"]
            )
        ]
    )

    submissions = hunt.process_query_results([{
        "file_content": "content from splunk",
        "source_system": "splunk"
    }])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    assert "source:splunk" in file_obs.tags
    assert "static_tag" in file_obs.tags


@pytest.mark.unit
def test_process_query_results_file_observable_with_all_properties(monkeypatch, tmpdir):
    """test F_FILE observable with directives, tags, and volatile all set"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import DIRECTIVE_SANDBOX, F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="fully_configured.txt",
                directives=[DIRECTIVE_SANDBOX],
                tags=["high_priority", "malware_candidate"],
                volatile=True
            )
        ]
    )

    submissions = hunt.process_query_results([{"file_content": "suspicious payload"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    # verify all properties are set correctly
    assert DIRECTIVE_SANDBOX in file_obs.directives
    assert "high_priority" in file_obs.tags
    assert "malware_candidate" in file_obs.tags
    assert file_obs.volatile


@pytest.mark.unit
def test_process_query_results_file_observable_with_grouping_and_properties(monkeypatch, tmpdir):
    """test F_FILE observable with directives, tags, and volatile when using group_by"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import DIRECTIVE_SANDBOX, F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_hunt",
        group_by="group_field",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="grouped_file.txt",
                directives=[DIRECTIVE_SANDBOX],
                tags=["grouped_tag"],
                volatile=False
            )
        ]
    )

    submissions = hunt.process_query_results([
        {"file_content": "content1", "group_field": "group_a"},
        {"file_content": "content2", "group_field": "group_a"},
    ])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 2

    for file_obs in file_observables:
        assert DIRECTIVE_SANDBOX in file_obs.directives
        assert "grouped_tag" in file_obs.tags
        assert not file_obs.volatile


@pytest.mark.unit
def test_process_query_results_with_ignored_values(monkeypatch, tmpdir):
    """test observable mapping with ignored_values"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_ignored_values",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip"],
                type="ipv4",
                ignored_values=[r"0\.0\.0\.0", r"127\.0\.0\.1"]
            )
        ]
    )

    # test with a value that should be ignored
    submissions = hunt.process_query_results([{"src_ip": "0.0.0.0"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # should only have F_SIGNATURE_ID observable, no ipv4 observable
    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 0

    # test with another ignored value
    submissions = hunt.process_query_results([{"src_ip": "127.0.0.1"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 0

    # test with a value that should NOT be ignored
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "1.2.3.4"


@pytest.mark.unit
def test_process_query_results_with_ignored_values_multiple_events(monkeypatch, tmpdir):
    """test ignored_values with multiple events, some ignored and some not"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_ignored_values",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip"],
                type="ipv4",
                ignored_values=[r"0\.0\.0\.0"]
            )
        ]
    )

    submissions = hunt.process_query_results([
        {"src_ip": "0.0.0.0"},
        {"src_ip": "1.2.3.4"},
        {"src_ip": "5.6.7.8"},
    ])
    assert submissions
    assert len(submissions) == 3

    # first submission should have no ipv4 observable (ignored)
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 0

    # second and third submissions should have ipv4 observables
    ipv4_observables = [o for o in submissions[1].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "1.2.3.4"

    ipv4_observables = [o for o in submissions[2].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "5.6.7.8"


@pytest.mark.unit
def test_process_query_results_with_display_type_and_value(monkeypatch, tmpdir):
    """test observable mapping with display_type and display_value"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_display_properties",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip"],
                type="ipv4",
                display_type="source_address",
                display_value="Source IP Address"
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    ipv4_obs = ipv4_observables[0]

    # display_type getter appends the actual type in parentheses
    assert ipv4_obs.display_type == "source_address (ipv4)"
    # display_value getter appends the actual value in parentheses
    assert ipv4_obs.display_value == "Source IP Address (1.2.3.4)"


@pytest.mark.unit
def test_process_query_results_with_display_type_only(monkeypatch, tmpdir):
    """test observable mapping with only display_type set"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_display_type",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip"],
                type="ipv4",
                display_type="source_ip"
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    ipv4_obs = ipv4_observables[0]

    # display_type getter appends the actual type in parentheses
    assert ipv4_obs.display_type == "source_ip (ipv4)"
    # display_value getter returns the actual value when _display_value is None
    assert ipv4_obs.display_value == "1.2.3.4"


@pytest.mark.unit
def test_process_query_results_with_display_value_only(monkeypatch, tmpdir):
    """test observable mapping with only display_value set"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_display_value",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip"],
                type="ipv4",
                display_value="Custom IP Display"
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    ipv4_obs = ipv4_observables[0]

    # display_type getter returns the actual type when _display_type is None
    assert ipv4_obs.display_type == "ipv4"
    # display_value getter appends the actual value in parentheses
    assert ipv4_obs.display_value == "Custom IP Display (1.2.3.4)"


@pytest.mark.unit
def test_process_query_results_file_observable_with_display_properties(monkeypatch, tmpdir):
    """test F_FILE observable with display_type and display_value

    NOTE: FileObservable overrides display_value as a read-only property that returns file_path,
    so ObservableMapping validation will fail if display_value is set for file type observables.
    """
    from pydantic import ValidationError

    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    # attempting to create an ObservableMapping with display_value for file type should fail validation
    with pytest.raises(ValidationError, match="display_value is not supported for file type observables"):
        ObservableMapping(
            fields=["file_content"],
            type=F_FILE,
            file_name="test_file.txt",
            display_type="email_attachment",
            display_value="Suspicious Email Attachment"
        )


@pytest.mark.unit
def test_process_query_results_file_observable_with_display_type_only(monkeypatch, tmpdir):
    """test F_FILE observable with only display_type set"""
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_display_type",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="test_file.txt",
                display_type="malware_sample"
            )
        ]
    )

    submissions = hunt.process_query_results([{"file_content": "malware data"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 1
    file_obs = file_observables[0]

    # display_type getter appends the actual type in parentheses
    assert file_obs.display_type == "malware_sample (file)"
    # display_value returns file_path for FileObservable (it's read-only)
    assert file_obs.display_value == "test_file.txt"


@pytest.mark.unit
def test_process_query_results_file_observable_with_grouped_display_properties(monkeypatch, tmpdir):
    """test F_FILE observable with display_type when using group_by

    NOTE: display_value cannot be set for file observables due to validation.
    """
    import saq.collectors.hunter.query_hunter
    from saq.constants import F_FILE

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_file_display_grouped",
        group_by="group_field",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["file_content"],
                type=F_FILE,
                file_name="grouped_file.txt",
                display_type="grouped_attachment"
            )
        ]
    )

    submissions = hunt.process_query_results([
        {"file_content": "content1", "group_field": "group_a"},
        {"file_content": "content2", "group_field": "group_a"},
    ])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    file_observables = [o for o in submission.root.observables if o.type == F_FILE]
    assert len(file_observables) == 2

    # verify display_type is set on grouped file observables
    for file_obs in file_observables:
        assert file_obs.display_type == "grouped_attachment (file)"


@pytest.mark.unit
def test_process_query_results_with_ignored_values_empty_list(monkeypatch, tmpdir):
    """test observable mapping with empty ignored_values list"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_empty_ignored",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip"],
                type="ipv4",
                ignored_values=[]
            )
        ]
    )

    # with empty ignored_values list, all values should be processed
    submissions = hunt.process_query_results([{"src_ip": "0.0.0.0"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "0.0.0.0"


@pytest.mark.unit
def test_process_query_results_with_ignored_values_regex(monkeypatch, tmpdir):
    """test that ignored_values supports regex patterns via re.fullmatch()"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_ignored_values_regex",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip"],
                type="ipv4",
                ignored_values=[r"10\.0\..*"]
            )
        ]
    )

    # 10.0.1.1 should be ignored by the regex pattern
    submissions = hunt.process_query_results([{"src_ip": "10.0.1.1"}])
    assert submissions
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 0

    # 10.0.255.3 should also be ignored
    submissions = hunt.process_query_results([{"src_ip": "10.0.255.3"}])
    assert submissions
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 0

    # 192.168.1.1 should NOT be ignored
    submissions = hunt.process_query_results([{"src_ip": "192.168.1.1"}])
    assert submissions
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "192.168.1.1"


@pytest.mark.unit
def test_observable_mapping_validation_display_value_for_file_type():
    """test that ObservableMapping validation prevents display_value for file type observables"""
    from pydantic import ValidationError

    from saq.constants import F_FILE

    # should raise ValidationError when trying to set display_value for file type
    with pytest.raises(ValidationError) as exc_info:
        ObservableMapping(
            fields=["file_content"],
            type=F_FILE,
            file_name="test.txt",
            display_value="Custom Display"
        )

    assert "display_value is not supported for file type observables" in str(exc_info.value)

    # display_type should be allowed for file type observables
    mapping = ObservableMapping(
        fields=["file_content"],
        type=F_FILE,
        file_name="test.txt",
        display_type="custom_file_type"
    )
    assert mapping.display_type == "custom_file_type"
    assert mapping.display_value is None


@pytest.mark.unit
def test_query_hunt_config_auto_append_default():
    """test that QueryHuntConfig has auto_append property with default empty string"""
    config = QueryHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="test_query",
        enabled=True,
        description="test description",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="test query",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False
    )

    assert hasattr(config, "auto_append")
    assert config.auto_append == ""


@pytest.mark.unit
def test_query_hunt_config_auto_append_custom():
    """test that QueryHuntConfig auto_append property can be set to custom value"""
    config = QueryHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="test_query",
        enabled=True,
        description="test description",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="test query",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append="| custom command"
    )

    assert config.auto_append == "| custom command"


@pytest.mark.unit
def test_process_query_results_with_relationship_mapping(monkeypatch):
    """test observable mapping with relationship to another observable"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_relationship",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            # target observable (hostname) - must be defined first so it exists when relationship is applied
            ObservableMapping(
                fields=["hostname"],
                type=F_HOSTNAME,
            ),
            # source observable (command_line) with relationship to hostname
            ObservableMapping(
                fields=["cmdline"],
                type=F_COMMAND_LINE,
                relationships=[
                    RelationshipMapping(
                        type=R_EXECUTED_ON,
                        target=RelationshipMappingTarget(
                            type=F_HOSTNAME,
                            value="${hostname}"
                        )
                    )
                ]
            ),
        ]
    )

    submissions = hunt.process_query_results([{
        "cmdline": "powershell.exe -enc AAAA",
        "hostname": "workstation01"
    }])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # find the command_line observable
    cmdline_observable = next((o for o in submission.root.observables if o.type == F_COMMAND_LINE), None)
    assert cmdline_observable is not None
    assert cmdline_observable.value == "powershell.exe -enc AAAA"

    # find the hostname observable
    hostname_observable = next((o for o in submission.root.observables if o.type == F_HOSTNAME), None)
    assert hostname_observable is not None
    assert hostname_observable.value == "workstation01"

    # verify the relationship exists
    assert len(cmdline_observable.relationships) == 1
    relationship = cmdline_observable.relationships[0]
    assert relationship.r_type == R_EXECUTED_ON
    assert relationship.target == hostname_observable


@pytest.mark.unit
def test_process_query_results_with_relationship_missing_target(monkeypatch):
    """test that relationship is skipped when target observable doesn't exist"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_relationship_missing",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            # source observable with relationship to a non-existent target
            ObservableMapping(
                fields=["cmdline"],
                type=F_COMMAND_LINE,
                relationships=[
                    RelationshipMapping(
                        type=R_EXECUTED_ON,
                        target=RelationshipMappingTarget(
                            type=F_HOSTNAME,
                            value="${hostname}"  # hostname field exists but no hostname observable mapping
                        )
                    )
                ]
            ),
        ]
    )

    # event has hostname field but no observable mapping creates a hostname observable
    submissions = hunt.process_query_results([{
        "cmdline": "powershell.exe -enc AAAA",
        "hostname": "workstation01"
    }])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # find the command_line observable
    cmdline_observable = next((o for o in submission.root.observables if o.type == F_COMMAND_LINE), None)
    assert cmdline_observable is not None

    # no hostname observable should exist
    hostname_observable = next((o for o in submission.root.observables if o.type == F_HOSTNAME), None)
    assert hostname_observable is None

    # relationship should not be created since target doesn't exist
    assert len(cmdline_observable.relationships) == 0


@pytest.mark.unit
def test_process_query_results_with_multiple_relationships(monkeypatch):
    """test observable with multiple relationships"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_multi_relationship",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            # target observables
            ObservableMapping(
                fields=["hostname"],
                type=F_HOSTNAME,
            ),
            ObservableMapping(
                fields=["src_ip"],
                type=F_IPV4,
            ),
            # source observable with multiple relationships
            ObservableMapping(
                fields=["cmdline"],
                type=F_COMMAND_LINE,
                relationships=[
                    RelationshipMapping(
                        type=R_EXECUTED_ON,
                        target=RelationshipMappingTarget(
                            type=F_HOSTNAME,
                            value="${hostname}"
                        )
                    ),
                    RelationshipMapping(
                        type=R_RELATED_TO,
                        target=RelationshipMappingTarget(
                            type=F_IPV4,
                            value="${src_ip}"
                        )
                    ),
                ]
            ),
        ]
    )

    submissions = hunt.process_query_results([{
        "cmdline": "powershell.exe -enc AAAA",
        "hostname": "workstation01",
        "src_ip": "192.168.1.100"
    }])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # find the command_line observable
    cmdline_observable = next((o for o in submission.root.observables if o.type == F_COMMAND_LINE), None)
    assert cmdline_observable is not None

    # verify both relationships exist
    assert len(cmdline_observable.relationships) == 2

    # check for executed_on relationship to hostname
    executed_on_rel = next((r for r in cmdline_observable.relationships if r.r_type == R_EXECUTED_ON), None)
    assert executed_on_rel is not None
    assert executed_on_rel.target.type == F_HOSTNAME
    assert executed_on_rel.target.value == "workstation01"

    # check for related_to relationship to ipv4
    related_to_rel = next((r for r in cmdline_observable.relationships if r.r_type == R_RELATED_TO), None)
    assert related_to_rel is not None
    assert related_to_rel.target.type == F_IPV4
    assert related_to_rel.target.value == "192.168.1.100"


@pytest.mark.unit
def test_process_query_results_with_relationship_and_grouping(monkeypatch):
    """test relationship mapping with grouped events"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_relationship_grouped",
        group_by="hostname",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["hostname"],
                type=F_HOSTNAME,
            ),
            ObservableMapping(
                fields=["cmdline"],
                type=F_COMMAND_LINE,
                relationships=[
                    RelationshipMapping(
                        type=R_EXECUTED_ON,
                        target=RelationshipMappingTarget(
                            type=F_HOSTNAME,
                            value="${hostname}"
                        )
                    )
                ]
            ),
        ]
    )

    submissions = hunt.process_query_results([
        {"cmdline": "cmd.exe /c dir", "hostname": "workstation01"},
        {"cmdline": "powershell.exe Get-Process", "hostname": "workstation01"},
        {"cmdline": "whoami", "hostname": "workstation02"},
    ])
    assert submissions
    assert len(submissions) == 2

    # find submission for workstation01
    ws01_submission = next((s for s in submissions if "workstation01" in s.root.description), None)
    assert ws01_submission is not None

    # find command_line observables for workstation01
    ws01_cmdlines = [o for o in ws01_submission.root.observables if o.type == F_COMMAND_LINE]
    assert len(ws01_cmdlines) == 2

    # each command_line should have a relationship to hostname
    ws01_hostname = next((o for o in ws01_submission.root.observables if o.type == F_HOSTNAME), None)
    assert ws01_hostname is not None

    for cmdline_obs in ws01_cmdlines:
        assert len(cmdline_obs.relationships) == 1
        assert cmdline_obs.relationships[0].r_type == R_EXECUTED_ON
        assert cmdline_obs.relationships[0].target == ws01_hostname


@pytest.mark.unit
def test_relationship_mapping_model_validation():
    """test RelationshipMapping and RelationshipMappingTarget Pydantic model validation"""
    from pydantic import ValidationError

    # valid relationship mapping
    mapping = RelationshipMapping(
        type=R_EXECUTED_ON,
        target=RelationshipMappingTarget(
            type=F_HOSTNAME,
            value="${hostname}"
        )
    )
    assert mapping.type == R_EXECUTED_ON
    assert mapping.target.type == F_HOSTNAME
    assert mapping.target.value == "${hostname}"

    # test that type is required for RelationshipMapping
    with pytest.raises(ValidationError):
        RelationshipMapping(
            target=RelationshipMappingTarget(type=F_HOSTNAME, value="test")
        )

    # test that target is required for RelationshipMapping
    with pytest.raises(ValidationError):
        RelationshipMapping(type=R_EXECUTED_ON)

    # test that type is required for RelationshipMappingTarget
    with pytest.raises(ValidationError):
        RelationshipMappingTarget(value="test")

    # test that value is required for RelationshipMappingTarget
    with pytest.raises(ValidationError):
        RelationshipMappingTarget(type=F_HOSTNAME)


@pytest.mark.unit
def test_process_query_results_with_relationship_static_target_value(monkeypatch):
    """test relationship with a static (non-interpolated) target value"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_static_relationship",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            # target observable with static value
            ObservableMapping(
                fields=["src_ip"],
                type=F_IPV4,
                value="10.0.0.1"  # static value
            ),
            # source observable with relationship to static target
            ObservableMapping(
                fields=["cmdline"],
                type=F_COMMAND_LINE,
                relationships=[
                    RelationshipMapping(
                        type=R_RELATED_TO,
                        target=RelationshipMappingTarget(
                            type=F_IPV4,
                            value="10.0.0.1"  # static value matching target
                        )
                    )
                ]
            ),
        ]
    )

    submissions = hunt.process_query_results([{
        "cmdline": "ping 10.0.0.1",
        "src_ip": "anything"  # field value is ignored due to static value in mapping
    }])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # find the command_line observable
    cmdline_observable = next((o for o in submission.root.observables if o.type == F_COMMAND_LINE), None)
    assert cmdline_observable is not None

    # find the ipv4 observable
    ipv4_observable = next((o for o in submission.root.observables if o.type == F_IPV4), None)
    assert ipv4_observable is not None
    assert ipv4_observable.value == "10.0.0.1"

    # verify the relationship exists
    assert len(cmdline_observable.relationships) == 1
    relationship = cmdline_observable.relationships[0]
    assert relationship.r_type == R_RELATED_TO
    assert relationship.target == ipv4_observable


@pytest.mark.unit
def test_description_field_with_grouping(monkeypatch):
    """test that description_field overrides group_by value in alert descriptions"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test",
        group_by="alert_id",
        description_field="alert_title",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ipv4")
        ]
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "alert_id": "id-001", "alert_title": "Suspicious Login"},
        {"src": "1.2.3.5", "alert_id": "id-001", "alert_title": "Suspicious Login"},
        {"src": "5.6.7.8", "alert_id": "id-002", "alert_title": "Malware Detected"},
    ])
    assert len(submissions) == 2

    for submission in submissions:
        # description should use alert_title, NOT alert_id
        assert "id-001" not in submission.root.description
        assert "id-002" not in submission.root.description
        assert "Suspicious Login" in submission.root.description or "Malware Detected" in submission.root.description


@pytest.mark.unit
def test_description_field_ungrouped(monkeypatch):
    """test that description_field appends to description when no grouping"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test",
        group_by=None,
        description_field="alert_title",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ipv4")
        ]
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "alert_title": "Suspicious Login"},
    ])
    assert len(submissions) == 1
    assert submissions[0].root.description == "test: Suspicious Login"


@pytest.mark.unit
def test_description_field_fallback_when_missing(monkeypatch):
    """test that when description_field is set but missing from event, falls back to group_by value"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test",
        group_by="alert_id",
        description_field="alert_title",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ipv4")
        ]
    )

    # event has alert_id but NOT alert_title
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "alert_id": "id-001"},
    ])
    assert len(submissions) == 1
    # should fall back to group_by value (alert_id)
    assert ": id-001" in submissions[0].root.description


@pytest.mark.unit
def test_description_field_ignored_for_group_all(monkeypatch):
    """test that description_field is ignored when group_by=ALL"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test",
        group_by="ALL",
        description_field="alert_title",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ipv4")
        ]
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "alert_title": "Suspicious Login"},
        {"src": "5.6.7.8", "alert_title": "Malware Detected"},
    ])
    assert len(submissions) == 1
    # description should NOT contain alert_title values — just name + event count
    assert submissions[0].root.description == "test (2 events)"


@pytest.mark.unit
def test_description_field_backward_compat(monkeypatch):
    """test that without description_field, behavior is identical to before"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test",
        group_by="src",
        description_field=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ipv4")
        ]
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "1.2.3.5"},
    ])
    assert len(submissions) == 2
    for submission in submissions:
        assert submission.root.description.endswith(": 1.2.3.4 (1 event)") or submission.root.description.endswith(": 1.2.3.5 (1 event)")


@pytest.mark.unit
def test_fields_mode_any_creates_separate_observables(monkeypatch):
    """test that fields_mode=any creates a separate observable for each present field"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_fields_mode_any",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip", "dst_ip"],
                type="ipv4",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 2
    values = sorted([o.value for o in ipv4_observables])
    assert values == ["1.2.3.4", "5.6.7.8"]


@pytest.mark.unit
def test_fields_mode_any_partial_fields(monkeypatch):
    """test that fields_mode=any creates observables only for present fields"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_fields_mode_any_partial",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip", "dst_ip"],
                type="ipv4",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    # only src_ip is present
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "1.2.3.4"


@pytest.mark.unit
def test_fields_mode_any_no_fields_present(monkeypatch):
    """test that fields_mode=any creates no observables when no fields are present"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_fields_mode_any_none",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip", "dst_ip"],
                type="ipv4",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    submissions = hunt.process_query_results([{"other_field": "value"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 0


@pytest.mark.unit
def test_fields_mode_any_with_value_raises_error():
    """test that fields_mode=any with value raises a validation error"""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="fields_mode='any' cannot be used with a custom 'value' template"):
        ObservableMapping(
            fields=["src_ip", "dst_ip"],
            type="ipv4",
            fields_mode=FieldsMode.ANY,
            value="${src_ip}:${dst_ip}"
        )


@pytest.mark.unit
def test_fields_mode_any_with_ignored_values(monkeypatch):
    """test that fields_mode=any skips ignored field values but creates observable for others"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_fields_mode_any_ignored",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip", "dst_ip"],
                type="ipv4",
                fields_mode=FieldsMode.ANY,
                ignored_values=[r"0\.0\.0\.0"]
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "0.0.0.0", "dst_ip": "5.6.7.8"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "5.6.7.8"


@pytest.mark.unit
def test_fields_mode_any_deduplicates(monkeypatch):
    """test that fields_mode=any deduplicates when two fields have the same value"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_fields_mode_any_dedup",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip", "dst_ip"],
                type="ipv4",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    # both fields have the same value
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4", "dst_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IPV4]
    # should deduplicate to one observable (create_observable returns same object for same type+value)
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "1.2.3.4"


@pytest.mark.unit
def test_fields_mode_all_explicit(monkeypatch):
    """test that fields_mode=all explicitly set behaves like default"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_fields_mode_all",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["src_ip", "dst_ip"],
                type="ipv4",
                fields_mode=FieldsMode.ALL,
                value="${src_ip}"
            )
        ]
    )

    # both fields present - should create observable
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}])
    assert submissions
    assert len(submissions) == 1
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "1.2.3.4"

    # one field missing - should NOT create observable
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IPV4]
    assert len(ipv4_observables) == 0