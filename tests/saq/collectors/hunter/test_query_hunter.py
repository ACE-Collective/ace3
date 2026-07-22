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
    QueryHunt,
    QueryHuntConfig,
)
from saq.configuration.config import get_config
from saq.configuration.schema import HuntTypeConfig
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    ANALYSIS_MODE_HTTP,
    F_COMMAND_LINE,
    F_HOSTNAME,
    F_IP,
    F_SIGNATURE_ID,
    R_EXECUTED_ON,
    R_RELATED_TO,
    SUMMARY_DETAIL_FORMAT_JINJA,
    SUMMARY_DETAIL_FORMAT_MD,
    SUMMARY_DETAIL_FORMAT_PRE,
    SUMMARY_DETAIL_FORMAT_TXT,
)
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.logging import DEFAULT_TRANSACTION_ID, get_transaction_id, transaction_id
from saq.observables.mapping import (
    FieldsMode,
    ObservableMapping,
    RelationshipMapping,
    RelationshipMappingTarget,
)
from saq.query.config import SummaryDetailConfig
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

    hunt_kwargs = {}
    if "manager" in kwargs:
        hunt_kwargs["manager"] = kwargs.pop("manager")

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

    return TestQueryHunt(config=config, **hunt_kwargs)

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
    shutil.copytree("tests/data/hunts/test/generic", temp_rules_dir)
    return str(temp_rules_dir)

@pytest.fixture(autouse=True, scope="function")
def setup(rules_dir):
    get_config().add_hunt_type_config("test_query",
        HuntTypeConfig(
            name='test_query',
            python_module='tests.saq.collectors.hunter.test_query_hunter',
            python_class='TestQueryHunt',
            rule_dirs=[{"rule_dir": rules_dir}],
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
    # end_time should catch up fully to current time (no gaps), not just one time_range
    assert hunt.end_time == current
    assert hunt.end_time - hunt.start_time == timedelta(hours=2)

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

    # full coverage end time (on time: exactly one time_range behind)
    hunt.config.full_coverage = True
    hunt.last_end_time = mock_local_time() - timedelta(hours=1)
    hunt.config.time_range = '01:00:00'
    assert hunt.end_time == hunt.last_end_time + hunt.time_range

    # full coverage, we're behind by one hour and max_time_range is not set:
    # we should fully catch up to now (no gaps)
    hunt.config.max_time_range = None
    hunt.last_end_time = mock_local_time() - timedelta(hours=2)
    assert hunt.end_time == mock_local_time()
    assert hunt.end_time - hunt.last_end_time == timedelta(hours=2)

    # full coverage, we're behind by one hour and max_time_range is set:
    # we can advance up to max_time_range from last_end_time
    hunt.last_end_time = mock_local_time() - timedelta(hours=3)
    hunt.config.max_time_range = '02:00:00'
    assert hunt.end_time == hunt.last_end_time + create_timedelta('02:00:00') # can go up to max time range

    # but no more than that at a time
    hunt.config.max_time_range = '08:00:00'
    hunt.last_end_time = mock_local_time() - timedelta(hours=9)
    assert hunt.end_time == hunt.last_end_time + timedelta(hours=8) # can go up to max time range

    # full coverage, slightly behind (less than time_range) with no max_time_range:
    # window should still end at now to avoid a small gap
    hunt.config.max_time_range = None
    hunt.last_end_time = mock_local_time() - timedelta(minutes=11)
    hunt.config.time_range = '00:10:00'
    assert hunt.end_time == mock_local_time()
    assert hunt.end_time - hunt.last_end_time == timedelta(minutes=11)

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
            ObservableMapping(fields=["src"], type="ip")
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
    assert submission.root.extensions == {
        "playbook_url": hunt.playbook_url,
        "transaction_id": get_transaction_id(),
    }

    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]
    assert len(submission.root.observables) == 2
    for observable in submission.root.observables:
        if observable.type == F_SIGNATURE_ID:
            assert observable.value == hunt.uuid
        elif observable.type == F_IP:
            assert observable.value == "1.2.3.4"
            assert not observable.volatile
        else:
            assert False, f"unexpected observable type: {observable.type}"

        assert not observable.time
        assert not observable.tags
        assert not observable.directives

    # test volatile observable
    hunt.config.observable_mapping = [
        ObservableMapping(fields=["src"], type="ip", volatile=True)
    ]
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]
    ipv4_observable = next((o for o in submission.root.observables if o.type == F_IP), None)
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
def test_process_query_results_templated_observable_type(monkeypatch):
    """A Jinja-templated observable type resolves per event, with fallback_type
       used (and an error logged) when the rendered type is not defined."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_templated_type",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="{{ kind }}", fallback_type="ip")
        ],
    )

    # rendered type is lowercased and resolved per event
    submissions = hunt.process_query_results([{"src": "1.2.3.4", "kind": "IP"}])
    assert len(submissions) == 1
    ipv4_observable = next((o for o in submissions[0].root.observables if o.type == F_IP), None)
    assert ipv4_observable is not None
    assert ipv4_observable.value == "1.2.3.4"

    # missing template field skips the observable silently (no fallback)
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert len(submissions) == 1
    assert [o.type for o in submissions[0].root.observables] == [F_SIGNATURE_ID]

    # unknown rendered type falls back to fallback_type
    submissions = hunt.process_query_results([{"src": "1.2.3.4", "kind": "not_a_type"}])
    assert len(submissions) == 1
    ipv4_observable = next((o for o in submissions[0].root.observables if o.type == F_IP), None)
    assert ipv4_observable is not None
    assert ipv4_observable.value == "1.2.3.4"

    # per-event resolution: one batch can emit different observable types
    hunt.config.group_by = "ALL"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "kind": "ip"},
        {"src": "host.example.com", "kind": "hostname"},
    ])
    assert len(submissions) == 1
    types = {o.type for o in submissions[0].root.observables}
    assert F_IP in types
    assert F_HOSTNAME in types


@pytest.mark.unit
def test_group_value_attached_to_submission(monkeypatch):
    """Each submission produced by a grouped hunt should carry its group_value
       so the manager can record per-group last_alert_time without re-deriving the grouping."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_group_value",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="src",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "5.6.7.8"},
    ])
    assert len(submissions) == 2
    group_values = sorted(s.group_value for s in submissions)
    assert group_values == ["1.2.3.4", "5.6.7.8"]

    # ALL grouping should produce a single submission tagged with "ALL"
    hunt.config.group_by = "ALL"
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "5.6.7.8"},
    ])
    assert len(submissions) == 1
    assert submissions[0].group_value == "ALL"


@pytest.mark.unit
def test_per_group_suppression_filters_recurring_group(monkeypatch):
    """When a group has alerted within the suppression window, that group's submission
       should be filtered out on the next run while other groups still pass through."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_per_group_supp",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        suppression="00:01:00",
        group_by="src",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    # first run: 1.2.3.4 alerts
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert len(submissions) == 1
    assert submissions[0].group_value == "1.2.3.4"

    # simulate the manager recording the alert post-execution
    hunt.set_last_alert_time(local_time(), "1.2.3.4")

    # second run with the same group plus a new one: only the new group passes through
    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "5.6.7.8"},
    ])
    assert len(submissions) == 1
    assert submissions[0].group_value == "5.6.7.8"


@pytest.mark.unit
def test_per_group_suppression_does_not_block_other_groups(monkeypatch):
    """Suppressing one group must not affect any other group."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_per_group_isolated",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        suppression="00:01:00",
        group_by="src",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    hunt.set_last_alert_time(local_time(), "1.2.3.4")

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "5.6.7.8"},
        {"src": "9.10.11.12"},
    ])
    group_values = sorted(s.group_value for s in submissions)
    assert group_values == ["5.6.7.8", "9.10.11.12"]


@pytest.mark.unit
def test_per_group_suppression_ignored_for_manual_hunt(monkeypatch, caplog):
    """A manual hunt (e.g. the validate-hunt API) must ignore suppression so the analyst
       sees the hunt's true output, even when a group alerted within the suppression window."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_per_group_supp_manual",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        suppression="00:01:00",
        group_by="src",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )
    hunt.manual_hunt = True

    # a recent alert for 1.2.3.4 would normally suppress that group
    hunt.set_last_alert_time(local_time(), "1.2.3.4")

    with caplog.at_level(logging.DEBUG):
        submissions = hunt.process_query_results([
            {"src": "1.2.3.4"},
            {"src": "5.6.7.8"},
        ])

    # both groups pass through; suppression is ignored for the manual run
    group_values = sorted(s.group_value for s in submissions)
    assert group_values == ["1.2.3.4", "5.6.7.8"]
    assert "ignoring suppression" in caplog.text


@pytest.mark.unit
def test_suppressed_property_false_when_group_by_set(monkeypatch):
    """Hunt.suppressed must return False for grouped hunts so HuntManager.execute
       does not gate-skip the entire hunt; per-group filtering happens after the query runs."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_suppressed_grouped",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        suppression="01:00:00",
        group_by="src",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    # write a recent hunt-level last_alert_time. for an ungrouped hunt this would mean
    # `suppressed` is True; for a grouped hunt the property must return False.
    hunt.last_alert_time = local_time()
    assert hunt.group_by is not None
    assert hunt.suppressed is False
    assert hunt.suppression_end is None


@pytest.mark.unit
def test_process_query_results_captures_original_events(monkeypatch):
    """When correlation is configured, the hunter should snapshot the raw event list
    before correlation mutates/filters it. For a normal (non-manual) non-correlate hunt
    the snapshot stays None to avoid an unnecessary deep copy on production runs."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    # case 1: no correlate -> original_query_results stays None
    hunt = default_hunt(
        manager=MockManager(),
        name="no_correlate",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )
    assert hunt.original_query_results is None
    hunt.process_query_results([{"src": "1.2.3.4"}, {"src": "5.6.7.8"}])
    assert hunt.original_query_results is None

    # case 2: correlate filters out one event -> snapshot keeps the full input
    correlate = CorrelateConfig.model_validate({
        "logic": [
            {
                "when": {"type": "equals", "value": "drop", "property": "tag"},
                "execute": [{"action": "filter"}],
            },
        ],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="with_correlate",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )

    input_events = [
        {"src": "1.2.3.4", "tag": "keep"},
        {"src": "5.6.7.8", "tag": "drop"},
        {"src": "9.9.9.9", "tag": "keep"},
    ]
    submissions = hunt.process_query_results(input_events)

    # the filter action removed one event from the final stream
    assert submissions is not None
    assert len(submissions) == 2

    # the snapshot has all three originals, in the original order
    assert hunt.original_query_results is not None
    assert len(hunt.original_query_results) == 3
    assert [e["src"] for e in hunt.original_query_results] == ["1.2.3.4", "5.6.7.8", "9.9.9.9"]
    assert [e["tag"] for e in hunt.original_query_results] == ["keep", "drop", "keep"]

    # every produced submission carries the originals on its root.details so they
    # persist with the alert (mirrors how correlation_trace is attached)
    for submission in submissions:
        assert "original_events" in submission.root.details
        assert submission.root.details["original_events"] is hunt.original_query_results
        assert [e["src"] for e in submission.root.details["original_events"]] == [
            "1.2.3.4", "5.6.7.8", "9.9.9.9",
        ]

    # snapshot must be a deep copy: mutating the snapshot must not affect the input
    # and mutating the input must not affect the snapshot
    hunt.original_query_results[0]["tag"] = "mutated"
    assert input_events[0]["tag"] == "keep"
    input_events[2]["tag"] = "mutated_again"
    assert hunt.original_query_results[2]["tag"] == "keep"


class _StubCorrelationResult:
    """Minimal stand-in for CorrelationEngine.execute()'s result so a unit test can
    exercise the post-correlation submission path without running real queries. The
    events are returned untouched (already carrying the correlated property)."""
    def __init__(self, events):
        self.trace = None
        self.captured_queries = []
        self.discarded = False
        self.events = events
        self.event_actions = {}
        self.alert_event_origin_indices = list(range(len(events)))


class _StubCorrelationEngine:
    def __init__(self, *args, **kwargs):
        pass

    def execute(self, query_results):
        return _StubCorrelationResult(query_results)


@pytest.mark.unit
def test_process_query_results_records_hunt_provenance(monkeypatch):
    """Correlated hunts attach per-observable step provenance to root.details so the GUI
    can group the Analysis Overview by the hunt step that produced each observable.

    Observables from initial-query fields map to step 0; observables from a correlation
    transform's named property map to that transform's step; an observable produced by
    both (here, an IP appearing in the initial query and the correlated results) carries
    both step indices."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    # don't run real correlation queries — events already carry the correlated property
    monkeypatch.setattr(
        "saq.collectors.hunter.correlation.engine.CorrelationEngine",
        _StubCorrelationEngine,
    )

    correlate = CorrelateConfig.model_validate({
        "logic": [
            {
                "description": "Check other activity from this IP",
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_type": "list",
                    "property_name": "correlate_logs",
                    "command": {"type": "query", "source": "splunk", "query": "index=x"},
                },
            },
        ],
    })

    hunt = default_hunt(
        manager=MockManager(),
        name="prov_hunt",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[
            ObservableMapping(fields=["src"], type=F_IP),  # initial query -> step 0
            ObservableMapping(fields=["correlate_logs.*.ip"], type=F_IP, field_lookup_type="dot"),      # -> step 1
            ObservableMapping(fields=["correlate_logs.*.host"], type=F_HOSTNAME, field_lookup_type="dot"),  # -> step 1
        ],
        correlate=correlate,
    )

    event = {
        "src": "1.2.3.4",
        "correlate_logs": [
            {"ip": "1.2.3.4", "host": "host-a"},  # ip shared with initial query
            {"ip": "9.9.9.9", "host": "host-b"},
        ],
    }
    submissions = hunt.process_query_results([event])
    assert len(submissions) == 1
    submission = submissions[0]

    provenance = submission.root.details["hunt_provenance"]

    # ordered steps: step 0 is the initial query, step 1 is the correlation transform
    assert provenance["steps"] == [
        {"index": 0, "label": "Initial Query", "property_name": None},
        {"index": 1, "label": "Check other activity from this IP", "property_name": "correlate_logs"},
    ]

    # resolve observable uuids by (type, value) so we can assert their step attribution
    uuid_by_spec = {(o.type, o.value): o.uuid for o in submission.root.observables}
    obs_map = provenance["observables"]

    assert obs_map[uuid_by_spec[(F_IP, "1.2.3.4")]] == [0, 1]   # initial + correlated
    assert obs_map[uuid_by_spec[(F_IP, "9.9.9.9")]] == [1]      # correlated only
    assert obs_map[uuid_by_spec[(F_HOSTNAME, "host-a")]] == [1]
    assert obs_map[uuid_by_spec[(F_HOSTNAME, "host-b")]] == [1]

    # the injected signature-id observable has no provenance and is left unattributed
    signature_id = next(o for o in submission.root.observables if o.type == F_SIGNATURE_ID)
    assert signature_id.uuid not in obs_map


@pytest.mark.unit
def test_process_query_results_no_provenance_without_correlate(monkeypatch):
    """Non-correlated hunts attach no hunt_provenance, so the GUI renders a flat tree."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="no_prov_hunt",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type=F_IP)],
    )
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert len(submissions) == 1
    assert "hunt_provenance" not in submissions[0].root.details

    # the no-correlate hunt produced submissions earlier; verify their details do
    # NOT contain original_events (the key is only attached when correlate ran)
    no_correlate_hunt = default_hunt(
        manager=MockManager(),
        name="no_correlate_check",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )
    no_correlate_subs = no_correlate_hunt.process_query_results([{"src": "1.2.3.4"}])
    assert no_correlate_subs
    for submission in no_correlate_subs:
        assert "original_events" not in submission.root.details


@pytest.mark.unit
def test_process_query_results_captures_original_events_for_manual_non_correlate(monkeypatch):
    """A manual/validate run of a non-correlate hunt snapshots the raw query results (so the
    validator can report exactly what the data source returned), but does NOT duplicate them
    into every root's details — those events already live in details["events"]."""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="manual_no_correlate",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )
    hunt.manual_hunt = True
    assert hunt.original_query_results is None

    input_events = [{"src": "1.2.3.4"}, {"src": "5.6.7.8"}, {"src": "9.9.9.9"}]
    submissions = hunt.process_query_results(input_events)

    # snapshot has every raw row, in the original order
    assert hunt.original_query_results is not None
    assert [e["src"] for e in hunt.original_query_results] == ["1.2.3.4", "5.6.7.8", "9.9.9.9"]

    # snapshot is a deep copy: mutating the input must not affect it
    input_events[0]["src"] = "0.0.0.0"
    assert hunt.original_query_results[0]["src"] == "1.2.3.4"

    # non-correlate roots are NOT bloated with a per-root copy of the originals
    assert submissions
    for submission in submissions:
        assert "original_events" not in submission.root.details


@pytest.mark.unit
def test_correlated_hunt_auto_tags_alert(monkeypatch):
    """ACE must auto-tag every alert from a correlated hunt with 'correlated'.
    Hunts without a `correlate:` block must not carry that tag.
    Auto-tag must not duplicate when the hunt YAML already lists it."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    base_kwargs = dict(
        manager=MockManager(),
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    hunt = default_hunt(name="no_correlate_tag", **base_kwargs)
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    for s in submissions:
        assert "correlated" not in s.root.tags

    correlate = CorrelateConfig.model_validate({"logic": [{"action": "alert"}]})
    hunt = default_hunt(name="with_correlate_tag", correlate=correlate, **base_kwargs)
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    for s in submissions:
        assert "correlated" in s.root.tags

    hunt = default_hunt(
        name="with_correlate_predeclared",
        correlate=correlate,
        tags=["correlated", "other_tag"],
        **base_kwargs,
    )
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    for s in submissions:
        assert s.root.tags.count("correlated") == 1
        assert "other_tag" in s.root.tags


@pytest.mark.unit
def test_correlation_trace_scoped_per_alert_no_grouping(monkeypatch):
    """Without group_by, two query results become two separate alerts. Each alert's
    correlation_trace should contain only the EventTrace for the event that produced
    that alert — not a copy of the whole hunt run's trace."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({
        "logic": [{"action": "alert"}],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_per_alert",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
        {"src": "5.6.7.8"},
    ])
    assert submissions and len(submissions) == 2

    # Hunt-level trace still holds both events (used by the hunt manager API).
    assert len(hunt.correlation_trace.event_traces) == 2

    # Each submission's trace should contain exactly one event_trace, and its
    # event_index must match the position of the event that produced it.
    traces = [s.root.details["correlation_trace"] for s in submissions]
    assert [len(t["event_traces"]) for t in traces] == [1, 1]
    assert traces[0]["event_traces"][0]["event_index"] == 0
    assert traces[1]["event_traces"][0]["event_index"] == 1
    # Stream events stay shared (hunt-level context); none here, so empty on both.
    assert traces[0]["stream_events"] == []
    assert traces[1]["stream_events"] == []

    # Without group_by, hunt_metadata still attaches but group_by is None.
    for s in submissions:
        hm = s.root.details["hunt_metadata"]
        assert hm["name"] == "trace_per_alert"
        assert hm["group_by"] is None
        assert hm["group_value"] is None

    # Per-event summaries fall back to extracted observable values when no
    # description_field/group_by are configured; the IP value should appear.
    assert traces[0]["event_traces"][0]["summary"] is not None
    assert "1.2.3.4" in traces[0]["event_traces"][0]["summary"]
    assert "5.6.7.8" in traces[1]["event_traces"][0]["summary"]


@pytest.mark.unit
def test_correlation_trace_scoped_per_alert_with_grouping(monkeypatch):
    """When events group into one alert, that alert's correlation_trace should
    contain every contributing event's EventTrace; sibling alerts in the same run
    only see their own events."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({
        "logic": [{"action": "alert"}],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_per_grouped_alert",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="msg_id",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )

    submissions = hunt.process_query_results([
        {"msg_id": "A", "src": "1.1.1.1"},
        {"msg_id": "A", "src": "2.2.2.2"},
        {"msg_id": "B", "src": "3.3.3.3"},
    ])
    assert submissions and len(submissions) == 2

    # Map each submission to its trace's set of event_indices.
    by_msg_id = {}
    for s in submissions:
        events_in_alert = s.root.details["events"]
        msg_id = events_in_alert[0]["msg_id"]
        by_msg_id[msg_id] = sorted(
            et["event_index"] for et in s.root.details["correlation_trace"]["event_traces"]
        )

    # Group A contributed indices 0 and 1; group B contributed index 2.
    assert by_msg_id == {"A": [0, 1], "B": [2]}

    # hunt_metadata is attached and carries the right group_by + group_value per submission.
    by_group = {}
    for s in submissions:
        hm = s.root.details["hunt_metadata"]
        assert hm["group_by"] == "msg_id"
        assert hm["name"] == "trace_per_grouped_alert"
        by_group[hm["group_value"]] = s
    assert set(by_group) == {"A", "B"}

    # Each EventTrace should carry a summary that mentions the group_value (msg_id).
    for group_value, s in by_group.items():
        for et in s.root.details["correlation_trace"]["event_traces"]:
            assert et["summary"], f"missing summary on {group_value}/{et['event_index']}"
            assert group_value in et["summary"]


@pytest.mark.unit
def test_hunt_metadata_name_renders_jinja(monkeypatch):
    """When the hunt name is itself a Jinja template, hunt_metadata.name should hold
    the rendered value (consistent with the alert description) rather than the raw
    template text — otherwise the Correlation Trace UI leaks the raw Jinja."""
    monkeypatch.setattr(query_hunter_module, "local_time", mock_local_time)

    # Name depends on an event field
    hunt = default_hunt(
        manager=MockManager(),
        name='Foo{{- " BAR" if has_x | list | length > 0 else "" -}}',
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([{"src": "1.2.3.4", "has_x": ["yes"]}])
    assert submissions and len(submissions) == 1
    hm = submissions[0].root.details["hunt_metadata"]
    assert hm["name"] == "Foo BAR"
    assert "{{" not in hm["name"]


@pytest.mark.unit
def test_hunt_metadata_name_plain_name_unchanged(monkeypatch):
    """A hunt name with no Jinja markers passes through _render_name's fast path and
    is stored verbatim in hunt_metadata."""
    monkeypatch.setattr(query_hunter_module, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="Plain Hunt Name",
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions and len(submissions) == 1
    assert submissions[0].root.details["hunt_metadata"]["name"] == "Plain Hunt Name"


@pytest.mark.unit
def test_event_trace_events_position_indexes_into_alert_events(monkeypatch):
    """Each scoped EventTrace should carry an `events_position` field that points at
    the entry in this submission's `details["events"]` list whose dict matches the
    trace event. The trace UI uses this to display the untruncated structured value
    of any property a transform step set on the event."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({"logic": [{"action": "alert"}]})

    # Ungrouped: each event becomes its own alert with events_position == 0.
    hunt = default_hunt(
        manager=MockManager(),
        name="events_position_no_group",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )
    submissions = hunt.process_query_results([
        {"src": "1.1.1.1"},
        {"src": "2.2.2.2"},
    ])
    assert submissions and len(submissions) == 2
    for s in submissions:
        events = s.root.details["events"]
        traces = s.root.details["correlation_trace"]["event_traces"]
        assert len(events) == 1 and len(traces) == 1
        pos = traces[0]["events_position"]
        assert pos == 0
        assert events[pos]["src"] == s.root.details["events"][0]["src"]

    # Grouped: a single submission can hold N events. events_position must index into
    # this submission's events list (not the hunt-wide one) and be 1:1 with the trace.
    hunt2 = default_hunt(
        manager=MockManager(),
        name="events_position_grouped",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="msg_id",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )
    submissions2 = hunt2.process_query_results([
        {"msg_id": "A", "src": "1.1.1.1"},
        {"msg_id": "B", "src": "2.2.2.2"},
        {"msg_id": "A", "src": "3.3.3.3"},
        {"msg_id": "A", "src": "4.4.4.4"},
    ])
    assert submissions2 and len(submissions2) == 2

    by_msg_id = {s.root.details["events"][0]["msg_id"]: s for s in submissions2}
    a_sub = by_msg_id["A"]
    a_events = a_sub.root.details["events"]
    a_traces = a_sub.root.details["correlation_trace"]["event_traces"]
    assert len(a_events) == 3 and len(a_traces) == 3
    # Each trace's events_position must point at an event with the same src as the
    # one the engine processed for that EventTrace.
    for et in a_traces:
        pos = et["events_position"]
        assert pos is not None
        assert 0 <= pos < len(a_events)
    # Positions must be unique within a submission (no two traces map to the same event).
    a_positions = sorted(et["events_position"] for et in a_traces)
    assert a_positions == [0, 1, 2]

    b_sub = by_msg_id["B"]
    b_traces = b_sub.root.details["correlation_trace"]["event_traces"]
    assert len(b_traces) == 1
    assert b_traces[0]["events_position"] == 0


@pytest.mark.unit
def test_event_summary_auto_derives_from_description_field_then_group_by(monkeypatch):
    """The auto-derived per-event summary should prefer description_field, then group_by,
    then observable values, in that order — and de-duplicate identical strings so the
    line stays short. This is what drives the collapsed-event header line in the trace UI.
    """
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({
        "logic": [{"action": "alert"}],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_summary_derivation",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="user",
        description_field="alert_title",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )

    submissions = hunt.process_query_results([
        {"alert_title": "Suspicious sign-in", "user": "alice@example.com", "src": "1.2.3.4"},
    ])
    assert submissions and len(submissions) == 1
    et = submissions[0].root.details["correlation_trace"]["event_traces"][0]
    summary = et["summary"]
    # All three signals must be present, in that order, separated by " · ".
    assert "Suspicious sign-in" in summary
    assert "alice@example.com" in summary
    assert "1.2.3.4" in summary
    assert summary.index("Suspicious sign-in") < summary.index("alice@example.com") < summary.index("1.2.3.4")

    # Description-field-only hunt: summary uses the description value and the observable;
    # group_by is None so it isn't appended.
    hunt2 = default_hunt(
        manager=MockManager(),
        name="trace_summary_no_group",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        description_field="alert_title",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )
    submissions2 = hunt2.process_query_results([
        {"alert_title": "Repeated event", "src": "9.9.9.9"},
    ])
    summary2 = submissions2[0].root.details["correlation_trace"]["event_traces"][0]["summary"]
    assert "Repeated event" in summary2
    assert "9.9.9.9" in summary2

    # When description_field value equals the group_by value, the summary
    # de-duplicates so the same string isn't repeated.
    hunt3 = default_hunt(
        manager=MockManager(),
        name="trace_summary_dedup",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="user",
        description_field="user",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )
    submissions3 = hunt3.process_query_results([
        {"user": "bob@example.com", "src": "8.8.8.8"},
    ])
    summary3 = submissions3[0].root.details["correlation_trace"]["event_traces"][0]["summary"]
    assert summary3.count("bob@example.com") == 1


@pytest.mark.unit
def test_event_summary_includes_event_time_as_trailing_part(monkeypatch):
    """The summary should include each event's timestamp as the trailing part so
    sibling events whose user / IP / other fields are identical are still
    distinguishable in the collapsed UI rows. Real-world example: a hunt may
    return two records emitted seconds apart for the same user from the same IP
    — without the time, the rows look like duplicates."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({"logic": [{"action": "alert"}]})

    hunt = default_hunt(
        manager=MockManager(),
        name="trace_summary_with_time",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="user",
        description_field=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )

    # The base QueryHunt's extract_event_timestamp returns None; subclasses
    # (e.g. SplunkHunt) parse a real timestamp out of the event. Stub it here.
    def fake_ts(event):
        raw = event.get("_time")
        return datetime.fromisoformat(raw) if raw else None
    monkeypatch.setattr(hunt, "extract_event_timestamp", fake_ts)

    submissions = hunt.process_query_results([
        {"user": "alice", "src": "1.1.1.1", "_time": "2026-05-08T15:48:47+00:00"},
        {"user": "alice", "src": "1.1.1.1", "_time": "2026-05-08T15:49:13+00:00"},
    ])
    assert submissions and len(submissions) == 1  # both grouped under "alice"

    traces = submissions[0].root.details["correlation_trace"]["event_traces"]
    summaries = [et["summary"] for et in traces]
    assert len(summaries) == 2
    # Both summaries end with their individual HH:MM:SS so analysts can pick
    # them apart at a glance.
    assert summaries[0].endswith("15:48:47")
    assert summaries[1].endswith("15:49:13")
    # The time is what makes them differ — without it the rows would be identical.
    assert summaries[0] != summaries[1]
    assert summaries[0].rsplit(" · ", 1)[0] == summaries[1].rsplit(" · ", 1)[0]

    # When extract_event_timestamp returns None (unsupported hunt type or
    # missing _time field), the summary just omits the time tail rather than
    # erroring. Use a fresh hunt; previously-stubbed events have _time set.
    hunt_no_time = default_hunt(
        manager=MockManager(),
        name="trace_summary_no_time",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        description_field=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )
    subs2 = hunt_no_time.process_query_results([{"src": "2.2.2.2"}])
    summary = subs2[0].root.details["correlation_trace"]["event_traces"][0]["summary"]
    # The base extract_event_timestamp returns None, so no time is appended;
    # only the IP observable shows up.
    assert summary == "2.2.2.2"


@pytest.mark.unit
def test_event_summary_dedupes_substrings_case_insensitive(monkeypatch):
    """The summary should drop a candidate that is a case-insensitive substring of
    any already-included part. In real hunts the description_field value tends
    to embed the user / email / msg_id that the group_by field and observables
    would also surface — without this dedup, the visible header repeats the same
    value 2-3x and the actually-differentiating part (e.g. an IP) gets clipped
    behind ellipsis. A candidate that supersedes an existing part replaces it.
    """
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({"logic": [{"action": "alert"}]})

    # Pattern: alert_title contains the userPrincipalName, the group_by IS the
    # userPrincipalName, and observables surface the lowercase email and an IP.
    # Only the IP differs across siblings.
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_summary_substring_dedup",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="userPrincipalName",
        description_field="alert_title",
        observable_mapping=[
            ObservableMapping(fields=["ip"], type="ip"),
            ObservableMapping(fields=["email"], type="email_address"),
        ],
        correlate=correlate,
    )
    submissions = hunt.process_query_results([
        {
            "alert_title": "JaneDoe@example.com + anonymizedIPAddress + TAP",
            "userPrincipalName": "JaneDoe@example.com",
            "ip": "192.0.2.42",
            "email": "janedoe@example.com",   # different case, still a substring of alert_title
        },
    ])
    summary = submissions[0].root.details["correlation_trace"]["event_traces"][0]["summary"]
    # Title and IP are both informative and present.
    assert "JaneDoe@example.com + anonymizedIPAddress + TAP" in summary
    assert "192.0.2.42" in summary
    # The user value should appear only once — the description_field already
    # contains it, so the group_by value and the (lowercased) email observable
    # are both dropped.
    assert summary.lower().count("janedoe@example.com") == 1
    # And the resulting summary uses ` · ` separators between parts.
    assert summary.count(" · ") == 1

    # Replacement case: when a later candidate fully supersedes an earlier one
    # (e.g. observable is more informative than the group_by value), the longer
    # candidate replaces the shorter so we don't lose information.
    hunt2 = default_hunt(
        manager=MockManager(),
        name="trace_summary_supersede",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="user",
        description_field=None,
        observable_mapping=[ObservableMapping(fields=["full_user"], type="email_address")],
        correlate=correlate,
    )
    submissions2 = hunt2.process_query_results([
        {"user": "alice", "full_user": "alice@example.com"},
    ])
    summary2 = submissions2[0].root.details["correlation_trace"]["event_traces"][0]["summary"]
    # The bare "alice" substring is dropped in favor of the more informative full email.
    assert "alice@example.com" in summary2
    assert summary2.count("alice") == 1


@pytest.mark.unit
def test_grouped_alert_includes_filtered_events_with_matching_group_value(monkeypatch):
    """For grouped hunts, filter-outcome event_traces whose original event shares
    the alert's group_by value SHOULD appear on that alert. This gives analysts the
    rejection context for the same key (e.g., "for this user, here's what was
    filtered alongside the kept events"). It also must not pollute sibling alerts
    that have a different group_by value — the original PR #185 behavior is
    preserved for cross-alert events."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    # Filter events tagged "drop"; everything else alerts. Two msg_id groups, one
    # of which has both kept and filtered events.
    correlate = CorrelateConfig.model_validate({
        "logic": [
            {
                "when": {"type": "equals", "value": "drop", "property": "tag"},
                "execute": [{"action": "filter"}],
            },
        ],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_filters_attached_grouped",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="msg_id",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )

    submissions = hunt.process_query_results([
        {"msg_id": "A", "src": "1.1.1.1", "tag": "keep"},   # idx 0 → A alert
        {"msg_id": "A", "src": "2.2.2.2", "tag": "drop"},   # idx 1 → filtered, A's
        {"msg_id": "B", "src": "3.3.3.3", "tag": "drop"},   # idx 2 → filtered, B has no alert
        {"msg_id": "A", "src": "4.4.4.4", "tag": "keep"},   # idx 3 → A alert
        {"msg_id": "C", "src": "5.5.5.5", "tag": "keep"},   # idx 4 → C alert
    ])
    assert submissions and len(submissions) == 2  # A and C; B got filtered with no alert

    by_msg_id = {s.root.details["events"][0]["msg_id"]: s for s in submissions}
    assert set(by_msg_id) == {"A", "C"}

    a_traces = by_msg_id["A"].root.details["correlation_trace"]["event_traces"]
    c_traces = by_msg_id["C"].root.details["correlation_trace"]["event_traces"]

    a_indices = sorted(et["event_index"] for et in a_traces)
    a_outcomes = sorted(et["outcome"] for et in a_traces)
    # Alert A keeps idx 0 and 3 (kept) and gains idx 1 (filtered, same msg_id).
    assert a_indices == [0, 1, 3]
    assert a_outcomes == ["alert", "alert", "filter"]

    # Alert C only gets its own kept event; B's filter (idx 2) doesn't leak in
    # because B has a different group_by value.
    c_indices = sorted(et["event_index"] for et in c_traces)
    c_outcomes = sorted(et["outcome"] for et in c_traces)
    assert c_indices == [4]
    assert c_outcomes == ["alert"]

    # The filter event added to A should still carry a useful summary derived from
    # the pre-correlation event (it's not in details["events"] for A).
    filter_et = next(et for et in a_traces if et["outcome"] == "filter")
    assert filter_et["summary"] is not None
    assert "A" in filter_et["summary"]
    # events_position is not set for extras — they don't have a slot in details["events"].
    assert filter_et["events_position"] is None


@pytest.mark.unit
def test_grouped_alert_includes_stop_outcome_events(monkeypatch):
    """`stop` is another way an event was rejected — analysts should see it on the
    alert for the same group_by value, like filter."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({
        "logic": [
            {
                "when": {"type": "equals", "value": "halt", "property": "tag"},
                "execute": [{"action": "stop"}],
            },
        ],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_stop_attached_grouped",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="msg_id",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )
    # The stop action breaks the engine loop entirely — once tripped, no later
    # events are processed. So put the stop event LAST so we still get an alert
    # for msg_id="A" before the stop.
    submissions = hunt.process_query_results([
        {"msg_id": "A", "src": "1.1.1.1", "tag": "keep"},
        {"msg_id": "A", "src": "2.2.2.2", "tag": "halt"},  # stop here
    ])
    assert submissions and len(submissions) == 1
    a_traces = submissions[0].root.details["correlation_trace"]["event_traces"]
    a_outcomes = sorted(et["outcome"] for et in a_traces)
    assert a_outcomes == ["alert", "stop"]


@pytest.mark.unit
def test_group_by_all_attaches_every_filtered_event(monkeypatch):
    """When group_by == "ALL", a hunt run produces a single submission. Every
    filtered event from the run goes on it."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({
        "logic": [
            {
                "when": {"type": "equals", "value": "drop", "property": "tag"},
                "execute": [{"action": "filter"}],
            },
        ],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_group_by_all",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by="ALL",
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )
    submissions = hunt.process_query_results([
        {"src": "1.1.1.1", "tag": "keep"},
        {"src": "2.2.2.2", "tag": "drop"},
        {"src": "3.3.3.3", "tag": "drop"},
        {"src": "4.4.4.4", "tag": "keep"},
    ])
    assert submissions and len(submissions) == 1
    traces = submissions[0].root.details["correlation_trace"]["event_traces"]
    assert sorted(et["event_index"] for et in traces) == [0, 1, 2, 3]
    assert sorted(et["outcome"] for et in traces) == ["alert", "alert", "filter", "filter"]


@pytest.mark.unit
def test_correlation_trace_filtered_event_not_attached_to_other_alerts(monkeypatch):
    """An event that the correlation engine filters out shouldn't appear in any
    alert's correlation_trace, even though it's still in the hunt-level trace."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    correlate = CorrelateConfig.model_validate({
        "logic": [
            {
                "when": {"type": "equals", "value": "drop", "property": "tag"},
                "execute": [{"action": "filter"}],
            },
        ],
    })
    hunt = default_hunt(
        manager=MockManager(),
        name="trace_filters_excluded",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        group_by=None,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
        correlate=correlate,
    )

    submissions = hunt.process_query_results([
        {"src": "1.1.1.1", "tag": "keep"},
        {"src": "2.2.2.2", "tag": "drop"},
        {"src": "3.3.3.3", "tag": "keep"},
    ])
    assert submissions and len(submissions) == 2

    # Hunt-level trace records all three events (one with outcome=filter).
    outcomes = [et.outcome for et in hunt.correlation_trace.event_traces]
    assert outcomes == ["alert", "filter", "alert"]

    # Each alert's trace only carries its own event_index — the filtered index 1
    # never appears in any alert.
    for s in submissions:
        indices = [et["event_index"] for et in s.root.details["correlation_trace"]["event_traces"]]
        assert 1 not in indices
        assert len(indices) == 1


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
                file_name="{{ filename }}"
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
    from saq.constants import F_FILE
    from saq.query.decoder import DecoderType

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
    from saq.constants import F_FILE
    from saq.query.decoder import DecoderType

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
                tags=["source:{{ source_system }}", "static_tag"]
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
def test_process_query_results_skips_unresolved_interpolated_tags(monkeypatch, tmpdir):
    """tags with unresolved interpolated placeholders should be omitted"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="test_unresolved_tags",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        tags=["mitre:{{ mitre_technique }}", "static_tag"],
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ip")
        ]
    )

    # event does NOT contain the 'mitre_technique' field
    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # the unresolved tag should be skipped, static tag should remain
    assert "static_tag" in submission.root.tags
    assert not any(tag.startswith("mitre:") for tag in submission.root.tags)

    # when the field IS present, the interpolated tag should be included
    submissions = hunt.process_query_results([{"src": "1.2.3.4", "mitre_technique": "T1204.002"}])
    assert submissions
    submission = submissions[0]
    assert "mitre:T1204.002" in submission.root.tags
    assert "static_tag" in submission.root.tags


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
                type="ip",
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
    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 0

    # test with another ignored value
    submissions = hunt.process_query_results([{"src_ip": "127.0.0.1"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 0

    # test with a value that should NOT be ignored
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
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
                type="ip",
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
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 0

    # second and third submissions should have ipv4 observables
    ipv4_observables = [o for o in submissions[1].root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "1.2.3.4"

    ipv4_observables = [o for o in submissions[2].root.observables if o.type == F_IP]
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
                type="ip",
                display_type="source_address",
                display_value="Source IP Address"
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 1
    ipv4_obs = ipv4_observables[0]

    # display_type getter appends the actual type in parentheses
    assert ipv4_obs.display_type == "source_address (ip)"
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
                type="ip",
                display_type="source_ip"
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 1
    ipv4_obs = ipv4_observables[0]

    # display_type getter appends the actual type in parentheses
    assert ipv4_obs.display_type == "source_ip (ip)"
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
                type="ip",
                display_value="Custom IP Display"
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 1
    ipv4_obs = ipv4_observables[0]

    # display_type getter returns the actual type when _display_type is None
    assert ipv4_obs.display_type == "ip"
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
                type="ip",
                ignored_values=[]
            )
        ]
    )

    # with empty ignored_values list, all values should be processed
    submissions = hunt.process_query_results([{"src_ip": "0.0.0.0"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
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
                type="ip",
                ignored_values=[r"10\.0\..*"]
            )
        ]
    )

    # 10.0.1.1 should be ignored by the regex pattern
    submissions = hunt.process_query_results([{"src_ip": "10.0.1.1"}])
    assert submissions
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 0

    # 10.0.255.3 should also be ignored
    submissions = hunt.process_query_results([{"src_ip": "10.0.255.3"}])
    assert submissions
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 0

    # 192.168.1.1 should NOT be ignored
    submissions = hunt.process_query_results([{"src_ip": "192.168.1.1"}])
    assert submissions
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IP]
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
                            value="{{ hostname }}"
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
                            value="{{ hostname }}"  # hostname field exists but no hostname observable mapping
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
                type=F_IP,
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
                            value="{{ hostname }}"
                        )
                    ),
                    RelationshipMapping(
                        type=R_RELATED_TO,
                        target=RelationshipMappingTarget(
                            type=F_IP,
                            value="{{ src_ip }}"
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
    assert related_to_rel.target.type == F_IP
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
                            value="{{ hostname }}"
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
            value="{{ hostname }}"
        )
    )
    assert mapping.type == R_EXECUTED_ON
    assert mapping.target.type == F_HOSTNAME
    assert mapping.target.value == "{{ hostname }}"

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
                type=F_IP,
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
                            type=F_IP,
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
    ipv4_observable = next((o for o in submission.root.observables if o.type == F_IP), None)
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
            ObservableMapping(fields=["src"], type="ip")
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
            ObservableMapping(fields=["src"], type="ip")
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
            ObservableMapping(fields=["src"], type="ip")
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
            ObservableMapping(fields=["src"], type="ip")
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
            ObservableMapping(fields=["src"], type="ip")
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
                type="ip",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
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
                type="ip",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    # only src_ip is present
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
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
                type="ip",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    submissions = hunt.process_query_results([{"other_field": "value"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 0


@pytest.mark.unit
def test_fields_mode_any_with_value_raises_error():
    """test that fields_mode=any with value raises a validation error"""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="fields_mode='any' cannot be used with a custom 'value' template"):
        ObservableMapping(
            fields=["src_ip", "dst_ip"],
            type="ip",
            fields_mode=FieldsMode.ANY,
            value="{{ src_ip }}:{{ dst_ip }}"
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
                type="ip",
                fields_mode=FieldsMode.ANY,
                ignored_values=[r"0\.0\.0\.0"]
            )
        ]
    )

    submissions = hunt.process_query_results([{"src_ip": "0.0.0.0", "dst_ip": "5.6.7.8"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
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
                type="ip",
                fields_mode=FieldsMode.ANY,
            )
        ]
    )

    # both fields have the same value
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4", "dst_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    ipv4_observables = [o for o in submission.root.observables if o.type == F_IP]
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
                type="ip",
                fields_mode=FieldsMode.ALL,
                value="{{ src_ip }}"
            )
        ]
    )

    # both fields present - should create observable
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}])
    assert submissions
    assert len(submissions) == 1
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 1
    assert ipv4_observables[0].value == "1.2.3.4"

    # one field missing - should NOT create observable
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert submissions
    assert len(submissions) == 1
    ipv4_observables = [o for o in submissions[0].root.observables if o.type == F_IP]
    assert len(ipv4_observables) == 0


@pytest.mark.unit
def test_process_query_results_with_relationship_missing_field(monkeypatch, caplog):
    """test that relationship is skipped with warning when target field is missing from event"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_relationship_missing_field",
        group_by=None,
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
                            type=F_IP,
                            value="{{ src_ip }}"  # src_ip is NOT in the event
                        )
                    )
                ]
            ),
        ]
    )

    with caplog.at_level(logging.WARNING):
        submissions = hunt.process_query_results([{
            "cmdline": "powershell.exe -enc AAAA",
            "hostname": "workstation01"
            # note: no src_ip field
        }])

    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    # alert should still be created with observables
    cmdline_observable = next((o for o in submission.root.observables if o.type == F_COMMAND_LINE), None)
    assert cmdline_observable is not None
    hostname_observable = next((o for o in submission.root.observables if o.type == F_HOSTNAME), None)
    assert hostname_observable is not None

    # relationship should NOT be created (field missing)
    assert len(cmdline_observable.relationships) == 0

    # warning should be logged
    assert any("skipping relationship" in record.message and "{{ src_ip }}" in record.message for record in caplog.records)


@pytest.mark.unit
def test_process_query_results_with_relationship_missing_dot_field(monkeypatch, caplog):
    """test that relationship is skipped with warning when $dot{} target field is missing from event"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_relationship_missing_dot_field",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["cmdline"],
                type=F_COMMAND_LINE,
                relationships=[
                    RelationshipMapping(
                        type=R_EXECUTED_ON,
                        target=RelationshipMappingTarget(
                            type=F_HOSTNAME,
                            value="{{ device.hostname }}"  # device.hostname is NOT in the event
                        )
                    )
                ]
            ),
        ]
    )

    with caplog.at_level(logging.WARNING):
        submissions = hunt.process_query_results([{
            "cmdline": "powershell.exe -enc AAAA",
            # note: no device.hostname field
        }])

    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    cmdline_observable = next((o for o in submission.root.observables if o.type == F_COMMAND_LINE), None)
    assert cmdline_observable is not None

    # relationship should NOT be created
    assert len(cmdline_observable.relationships) == 0

    # warning should be logged
    assert any("skipping relationship" in record.message and "{{ device.hostname }}" in record.message for record in caplog.records)


@pytest.mark.unit
def test_process_query_results_with_relationship_partial_field_resolution(monkeypatch, caplog):
    """test that relationship is skipped when composite target has one field missing"""
    import saq.collectors.hunter.query_hunter

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_relationship_partial_resolution",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(
                fields=["cmdline"],
                type=F_COMMAND_LINE,
                relationships=[
                    RelationshipMapping(
                        type=R_EXECUTED_ON,
                        target=RelationshipMappingTarget(
                            type=F_HOSTNAME,
                            value="{{ user }}@{{ hostname }}"  # hostname is missing
                        )
                    )
                ]
            ),
        ]
    )

    with caplog.at_level(logging.WARNING):
        submissions = hunt.process_query_results([{
            "cmdline": "powershell.exe -enc AAAA",
            "user": "admin",
            # note: no hostname field
        }])

    assert submissions
    assert len(submissions) == 1
    submission = submissions[0]

    cmdline_observable = next((o for o in submission.root.observables if o.type == F_COMMAND_LINE), None)
    assert cmdline_observable is not None

    # relationship should NOT be created (partial resolution)
    assert len(cmdline_observable.relationships) == 0

    # warning should be logged mentioning the raw template with the missing field
    assert any("skipping relationship" in record.message and "{{ user }}@{{ hostname }}" in record.message for record in caplog.records)


@pytest.mark.unit
def test_dedup_key_config_field():
    """test that dedup_key field is parsed correctly in QueryHuntConfig"""
    config = QueryHuntConfig(
        uuid="test-uuid",
        name="test",
        type="test",
        enabled=True,
        description="test",
        alert_type="test",
        frequency="01:00:00",
        tags=[],
        instance_types=[],
        time_range="01:00:00",
        full_coverage=True,
        use_index_time=True,
        query="test",
        dedup_key="{{ correlationId }}",
    )
    assert config.dedup_key == "{{ correlationId }}"


@pytest.mark.unit
def test_dedup_key_config_default_none():
    """test that dedup_key defaults to None when not set"""
    config = QueryHuntConfig(
        uuid="test-uuid",
        name="test",
        type="test",
        enabled=True,
        description="test",
        alert_type="test",
        frequency="01:00:00",
        tags=[],
        instance_types=[],
        time_range="01:00:00",
        full_coverage=True,
        use_index_time=True,
        query="test",
    )
    assert config.dedup_key is None


@pytest.mark.unit
def test_dedup_key_ungrouped(monkeypatch):
    """test that submission.key is set when dedup_key is configured (ungrouped)"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_dedup",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ip")
        ],
        dedup_key="{{ correlationId }}",
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "correlationId": "abc-123"},
    ])
    assert len(submissions) == 1
    assert submissions[0].key == f"{hunt.uuid}:abc-123"


@pytest.mark.unit
def test_dedup_key_ungrouped_composite(monkeypatch):
    """test that dedup_key works with composite interpolation templates"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_dedup_composite",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ip")
        ],
        dedup_key="{{ user }}-{{ src_ip }}",
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "user": "jdoe", "src_ip": "10.0.0.1"},
    ])
    assert len(submissions) == 1
    assert submissions[0].key == f"{hunt.uuid}:jdoe-10.0.0.1"


@pytest.mark.unit
def test_dedup_key_grouped(monkeypatch):
    """test that submission.key is set when dedup_key is configured (grouped)"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_dedup_grouped",
        group_by="id",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ip")
        ],
        dedup_key="{{ id }}",
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "id": "event-001"},
        {"src": "1.2.3.5", "id": "event-001"},
        {"src": "5.6.7.8", "id": "event-002"},
    ])
    assert len(submissions) == 2

    # find submissions by their dedup key
    keys = {s.key for s in submissions}
    assert f"{hunt.uuid}:event-001" in keys
    assert f"{hunt.uuid}:event-002" in keys


@pytest.mark.unit
def test_dedup_key_none_when_not_set(monkeypatch):
    """test that submission.key is None when dedup_key is not configured"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_no_dedup",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ip")
        ],
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
    ])
    assert len(submissions) == 1
    assert submissions[0].key is None


@pytest.mark.unit
def test_dedup_key_includes_hunt_uuid_prefix(monkeypatch):
    """test that dedup key always includes the hunt UUID as prefix"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_dedup_prefix",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ip")
        ],
        dedup_key="{{ id }}",
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "id": "some-value"},
    ])
    assert len(submissions) == 1
    key = submissions[0].key
    assert key.startswith(f"{hunt.uuid}:")
    assert key == f"{hunt.uuid}:some-value"


@pytest.mark.unit
def test_dedup_key_missing_field_returns_none(monkeypatch):
    """test that submission.key is None when dedup_key references a missing field"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_dedup_missing",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[
            ObservableMapping(fields=["src"], type="ip")
        ],
        dedup_key="{{ nonexistent_field }}",
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4"},
    ])
    assert len(submissions) == 1
    assert submissions[0].key is None


# ============================================================================
# Summary Detail Tests
# ============================================================================

@pytest.mark.unit
def test_summary_detail_config_defaults():
    """test that SummaryDetailConfig has correct defaults when only content is set"""
    config = SummaryDetailConfig(content="test content")
    assert config.content == "test content"
    assert config.header is None
    assert config.format == SUMMARY_DETAIL_FORMAT_MD
    assert config.limit == 100
    assert config.grouped is False


@pytest.mark.unit
def test_summary_detail_config_invalid_format(caplog):
    """test that invalid format falls back to MD and logs error"""
    with caplog.at_level(logging.ERROR):
        config = SummaryDetailConfig(content="test", format="invalid")
    assert config.format == SUMMARY_DETAIL_FORMAT_MD
    assert "invalid summary_detail format" in caplog.text


@pytest.mark.unit
@pytest.mark.parametrize("fmt", [SUMMARY_DETAIL_FORMAT_MD, SUMMARY_DETAIL_FORMAT_PRE, SUMMARY_DETAIL_FORMAT_TXT])
def test_summary_detail_config_valid_formats(fmt):
    """test that all valid formats are accepted"""
    config = SummaryDetailConfig(content="test", format=fmt)
    assert config.format == fmt


@pytest.mark.unit
def test_hunt_config_with_summary_details():
    """test that summary_details field is accepted on QueryHuntConfig"""
    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_config",
        summary_details=[
            SummaryDetailConfig(content="test {{ field }}"),
        ],
    )
    assert len(hunt.config.summary_details) == 1
    assert hunt.config.summary_details[0].content == "test {{ field }}"


@pytest.mark.unit
def test_summary_details_empty_list(monkeypatch):
    """test backward compatibility - empty summary_details does nothing"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_empty",
        group_by=None,
        summary_details=[],
    )
    submissions = hunt.process_query_results([{"field1": "value1"}])
    assert len(submissions) == 1
    assert len(submissions[0].root.summary_details) == 0


@pytest.mark.unit
def test_summary_details_ungrouped_basic(monkeypatch):
    """test ungrouped summary detail with single event"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_basic",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(content="IP: {{ src_ip }}", header="Source IPs", format=SUMMARY_DETAIL_FORMAT_PRE),
        ],
    )
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 1
    assert sd_list[0].header == "Source IPs"
    assert sd_list[0].content == "IP: 1.2.3.4"
    assert sd_list[0].format == SUMMARY_DETAIL_FORMAT_PRE


@pytest.mark.unit
def test_summary_details_ungrouped_multiple_events(monkeypatch):
    """test ungrouped - multiple events without group_by, each gets own detail"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_multi",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(content="{{ host }}"),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1"},
        {"host": "server2"},
    ])
    assert len(submissions) == 2
    assert submissions[0].root.summary_details[0].content == "server1"
    assert submissions[1].root.summary_details[0].content == "server2"


@pytest.mark.unit
def test_summary_details_ungrouped_missing_field_skipped(monkeypatch):
    """test that events with missing fields are silently skipped"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_missing",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(content="{{ missing_field }}"),
        ],
    )
    submissions = hunt.process_query_results([{"other": "value"}])
    assert len(submissions) == 1
    assert len(submissions[0].root.summary_details) == 0


@pytest.mark.unit
def test_summary_details_ungrouped_limit(monkeypatch, caplog):
    """test that limit is enforced and warning is logged"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_limit",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(content="{{ val }}", limit=2),
        ],
    )
    events = [{"val": f"v{i}"} for i in range(5)]
    with caplog.at_level(logging.WARNING):
        submissions = hunt.process_query_results(events)
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 2
    assert sd_list[0].content == "v0"
    assert sd_list[1].content == "v1"
    assert "summary detail limit (2) reached" in caplog.text


@pytest.mark.unit
def test_summary_details_ungrouped_no_header(monkeypatch):
    """test that header=None passes through correctly"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_no_header",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(content="{{ val }}"),
        ],
    )
    submissions = hunt.process_query_results([{"val": "test"}])
    assert len(submissions) == 1
    assert submissions[0].root.summary_details[0].header is None
    assert submissions[0].root.summary_details[0].content == "test"


@pytest.mark.unit
def test_summary_details_ungrouped_multiple_definitions(monkeypatch):
    """test that two definitions produce independent details"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_multi_def",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(content="{{ src }}", header="Source"),
            SummaryDetailConfig(content="{{ dst }}", header="Dest"),
        ],
    )
    submissions = hunt.process_query_results([{"src": "1.2.3.4", "dst": "5.6.7.8"}])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 2
    assert sd_list[0].header == "Source"
    assert sd_list[0].content == "1.2.3.4"
    assert sd_list[1].header == "Dest"
    assert sd_list[1].content == "5.6.7.8"


@pytest.mark.unit
def test_summary_details_grouped_with_group_by(monkeypatch):
    """test grouped summary detail - multiple events combined with newline"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_grouped",
        group_by="group_field",
        summary_details=[
            SummaryDetailConfig(content="{{ host }}", header="Hosts", grouped=True),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1", "group_field": "group_a"},
        {"host": "server2", "group_field": "group_a"},
        {"host": "server3", "group_field": "group_b"},
    ])
    assert len(submissions) == 2
    group_a = next(s for s in submissions if "group_a" in s.root.description)
    group_b = next(s for s in submissions if "group_b" in s.root.description)

    assert len(group_a.root.summary_details) == 1
    assert group_a.root.summary_details[0].content == "server1\nserver2"
    assert group_a.root.summary_details[0].header == "Hosts"

    assert len(group_b.root.summary_details) == 1
    assert group_b.root.summary_details[0].content == "server3"


@pytest.mark.unit
def test_summary_details_grouped_missing_field_skipped(monkeypatch):
    """test grouped - events with missing fields are skipped, others still contribute"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_grouped_missing",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(content="{{ host }}", grouped=True),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1"},
        {"other": "value"},
        {"host": "server3"},
    ])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 1
    assert sd_list[0].content == "server1\nserver3"


@pytest.mark.unit
def test_summary_details_grouped_limit(monkeypatch, caplog):
    """test grouped limit caps collected lines and logs warning"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_grouped_limit",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(content="{{ val }}", grouped=True, limit=2),
        ],
    )
    events = [{"val": f"line{i}"} for i in range(5)]
    with caplog.at_level(logging.WARNING):
        submissions = hunt.process_query_results(events)
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 1
    assert sd_list[0].content == "line0\nline1"
    assert "summary detail limit (2) reached" in caplog.text


@pytest.mark.unit
def test_summary_details_grouped_no_matching_events(monkeypatch):
    """test grouped - no summary detail added when all events are skipped"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_grouped_none",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(content="{{ missing }}", grouped=True),
        ],
    )
    submissions = hunt.process_query_results([
        {"other": "value1"},
        {"other": "value2"},
    ])
    assert len(submissions) == 1
    assert len(submissions[0].root.summary_details) == 0


@pytest.mark.unit
def test_summary_details_mixed_grouped_and_ungrouped(monkeypatch):
    """test two definitions, one grouped and one ungrouped"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_mixed",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(content="{{ host }}", header="Individual Hosts"),
            SummaryDetailConfig(content="{{ host }}", header="All Hosts", grouped=True),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1"},
        {"host": "server2"},
    ])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    # ungrouped: 2 details (one per event), grouped: 1 detail (combined)
    assert len(sd_list) == 3
    ungrouped = [sd for sd in sd_list if sd.header == "Individual Hosts"]
    grouped = [sd for sd in sd_list if sd.header == "All Hosts"]
    assert len(ungrouped) == 2
    assert {sd.content for sd in ungrouped} == {"server1", "server2"}
    assert len(grouped) == 1
    assert grouped[0].content == "server1\nserver2"


@pytest.mark.integration
def test_load_hunt_yaml_with_summary_details(rules_dir, manager_kwargs):
    """test that a YAML file with summary_details loads correctly"""
    test_yaml_path = os.path.join(rules_dir, "test_sd.yaml")
    with open(test_yaml_path, "w") as fp:
        yaml.dump({
            "rule": {
                "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "enabled": "yes",
                "name": "summary_detail_test",
                "description": "Test Hunt with Summary Details",
                "type": "test_query",
                "alert_type": "test - query",
                "frequency": "00:01:00",
                "tags": ["tag1"],
                "time_range": "00:01:00",
                "full_coverage": "yes",
                "group_by": "field1",
                "query": "index=test",
                "use_index_time": "yes",
                "instance_types": ["unittest"],
                "summary_details": [
                    {
                        "content": "Host: {{ hostname }}",
                        "header": "Hosts",
                        "format": "pre",
                        "limit": 50,
                        "grouped": True,
                    },
                    {
                        "content": "{{ message }}",
                    },
                ],
            },
        }, fp, default_flow_style=False)

    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()

    hunt = next((h for h in manager.hunts if h.name == "summary_detail_test"), None)
    assert hunt is not None
    assert len(hunt.config.summary_details) == 2

    sd0 = hunt.config.summary_details[0]
    assert sd0.content == "Host: {{ hostname }}"
    assert sd0.header == "Hosts"
    assert sd0.format == SUMMARY_DETAIL_FORMAT_PRE
    assert sd0.limit == 50
    assert sd0.grouped is True

    sd1 = hunt.config.summary_details[1]
    assert sd1.content == "{{ message }}"
    assert sd1.header is None
    assert sd1.format == SUMMARY_DETAIL_FORMAT_MD
    assert sd1.limit == 100
    assert sd1.grouped is False


# --- Jinja format tests ---


@pytest.mark.unit
def test_summary_details_jinja_basic(monkeypatch):
    """Test Jinja format rendering through process_query_results."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_jinja",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(content="IP: {{ src_ip }}", format=SUMMARY_DETAIL_FORMAT_JINJA),
        ],
    )
    submissions = hunt.process_query_results([{"src_ip": "1.2.3.4"}])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 1
    assert sd_list[0].content == "IP: 1.2.3.4"
    assert sd_list[0].format == SUMMARY_DETAIL_FORMAT_JINJA


@pytest.mark.unit
def test_summary_details_jinja_missing_field_strict_skipped(monkeypatch):
    """Test Jinja format with missing field in strict mode — event is skipped."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_jinja_strict",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(content="{{ missing }}", format=SUMMARY_DETAIL_FORMAT_JINJA),
        ],
    )
    submissions = hunt.process_query_results([{"other": "value"}])
    assert len(submissions) == 1
    assert len(submissions[0].root.summary_details) == 0


# --- Dedup fields tests ---


@pytest.mark.unit
def test_summary_details_dedup_with_group_by(monkeypatch):
    """Test dedup with group_by — per-submission dedup."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_dedup",
        group_by="group_field",
        summary_details=[
            SummaryDetailConfig(content="{{ host }}", dedup_fields=["host"]),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1", "group_field": "group_a"},
        {"host": "server1", "group_field": "group_a"},
        {"host": "server2", "group_field": "group_a"},
    ])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    # server1 appears only once (deduped), server2 also appears
    assert len(sd_list) == 2
    contents = {sd.content for sd in sd_list}
    assert contents == {"server1", "server2"}


@pytest.mark.unit
def test_summary_details_dedup_grouped(monkeypatch):
    """Test dedup with grouped summary details."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_dedup_grouped",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(content="{{ host }}", grouped=True, dedup_fields=["host"]),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1"},
        {"host": "server1"},
        {"host": "server2"},
    ])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 1
    assert sd_list[0].content == "server1\nserver2"


# --- Required fields tests ---


@pytest.mark.unit
def test_summary_details_required_fields(monkeypatch):
    """Test required_fields through process_query_results."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_required",
        group_by=None,
        summary_details=[
            SummaryDetailConfig(
                content="{{ src_ip }}",
                required_fields=["src_ip"],
            ),
        ],
    )
    submissions = hunt.process_query_results([
        {"src_ip": "10.0.0.1"},
        {"other": "value"},
    ])
    assert len(submissions) == 2
    assert len(submissions[0].root.summary_details) == 1
    assert submissions[0].root.summary_details[0].content == "10.0.0.1"
    assert len(submissions[1].root.summary_details) == 0


# --- YAML loading tests ---


@pytest.mark.integration
def test_load_hunt_yaml_with_jinja_and_new_fields(rules_dir, manager_kwargs):
    """Test that a YAML file with jinja format and new fields loads correctly."""
    test_yaml_path = os.path.join(rules_dir, "test_sd_jinja.yaml")
    with open(test_yaml_path, "w") as fp:
        yaml.dump({
            "rule": {
                "uuid": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "enabled": "yes",
                "name": "jinja_test",
                "description": "Jinja Test Hunt",
                "type": "test_query",
                "alert_type": "test - query",
                "frequency": "00:01:00",
                "tags": ["tag1"],
                "time_range": "00:01:00",
                "full_coverage": "yes",
                "group_by": "field1",
                "query": "index=test",
                "use_index_time": "yes",
                "instance_types": ["unittest"],
                "summary_details": [
                    {
                        "content": "IP: {{ src_ip }}",
                        "header": "IPs",
                        "format": "jinja",
                        "dedup_fields": ["src_ip"],
                        "required_fields": ["src_ip"],
                    },
                ],
            },
        }, fp, default_flow_style=False)

    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()

    hunt = next((h for h in manager.hunts if h.name == "jinja_test"), None)
    assert hunt is not None
    assert len(hunt.config.summary_details) == 1

    sd0 = hunt.config.summary_details[0]
    assert sd0.content == "IP: {{ src_ip }}"
    assert sd0.format == SUMMARY_DETAIL_FORMAT_JINJA
    assert sd0.dedup_fields == ["src_ip"]
    assert sd0.required_fields == ["src_ip"]


# --- Grouped + Jinja tests ---


@pytest.mark.unit
def test_summary_details_grouped_jinja_renders_per_submission(monkeypatch):
    """Test grouped + Jinja renders per-submission with events list."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_grouped_jinja",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(
                content="{% for event in events %}{{ event.host }}\n{% endfor %}",
                header="All Hosts",
                format=SUMMARY_DETAIL_FORMAT_JINJA,
                grouped=True,
                required_fields=["host"],
            ),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1"},
        {"host": "server2"},
        {"host": "server3"},
    ])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 1
    assert sd_list[0].format == SUMMARY_DETAIL_FORMAT_JINJA
    assert sd_list[0].header == "All Hosts"
    assert "server1" in sd_list[0].content
    assert "server2" in sd_list[0].content
    assert "server3" in sd_list[0].content


@pytest.mark.unit
def test_summary_details_grouped_jinja_dedup_per_submission(monkeypatch):
    """Test grouped + Jinja with dedup per-submission."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_grouped_jinja_dedup",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(
                content="{% for event in events %}{{ event.host }}\n{% endfor %}",
                format=SUMMARY_DETAIL_FORMAT_JINJA,
                grouped=True,
                dedup_fields=["host"],
                required_fields=["host"],
            ),
        ],
    )
    submissions = hunt.process_query_results([
        {"host": "server1"},
        {"host": "server1"},
        {"host": "server2"},
    ])
    assert len(submissions) == 1
    sd_list = submissions[0].root.summary_details
    assert len(sd_list) == 1
    # server1 should appear only once due to dedup
    assert sd_list[0].content.count("server1") == 1
    assert "server2" in sd_list[0].content


@pytest.mark.unit
def test_summary_details_grouped_jinja_missing_field_does_not_kill_alert(monkeypatch):
    """A missing field in a grouped Jinja summary detail (strict mode) must drop just that
    block and still produce the alert — not raise out of process_query_results.

    Regression: with no required_fields the grouped-Jinja render runs under StrictUndefined,
    so an event lacking a referenced key raised UndefinedError that bubbled up and killed the
    whole hunt instead of isolating the failure to the summary detail.
    """
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="test_sd_grouped_jinja_missing",
        group_by="ALL",
        summary_details=[
            SummaryDetailConfig(
                # references event.sometimes, which the second event lacks -> UndefinedError
                content="{% for event in events %}{{ event.always }}/{{ event.sometimes }}\n{% endfor %}",
                format=SUMMARY_DETAIL_FORMAT_JINJA,
                grouped=True,
            ),
        ],
    )
    # must not raise
    submissions = hunt.process_query_results([
        {"always": "a", "sometimes": "x"},
        {"always": "b"},
    ])
    assert len(submissions) == 1
    # the faulty block is dropped, but the alert still fires
    assert len(submissions[0].root.summary_details) == 0


@pytest.mark.unit
def test_query_with_suffix():
    """test that query_suffix is appended to the query with a newline separator"""
    hunt = default_hunt(query="index=test sourcetype=test", query_suffix="| stats count")
    assert hunt.query == "index=test sourcetype=test\n| stats count"


@pytest.mark.unit
def test_query_with_prefix():
    """test that query_prefix is prepended to the query with a newline separator"""
    hunt = default_hunt(query="index=test sourcetype=test", query_prefix="| inputlookup test.csv")
    assert hunt.query == "| inputlookup test.csv\nindex=test sourcetype=test"


@pytest.mark.unit
def test_query_with_prefix_and_suffix():
    """test that both query_prefix and query_suffix are applied"""
    hunt = default_hunt(
        query="index=test sourcetype=test",
        query_prefix="| inputlookup test.csv",
        query_suffix="| stats count",
    )
    assert hunt.query == "| inputlookup test.csv\nindex=test sourcetype=test\n| stats count"


@pytest.mark.unit
def test_query_with_no_prefix_or_suffix():
    """test that query is unchanged when no prefix or suffix is set"""
    hunt = default_hunt(query="index=test sourcetype=test")
    assert hunt.query == "index=test sourcetype=test"


@pytest.mark.unit
def test_query_with_empty_string_prefix_and_suffix():
    """test that empty strings are treated the same as None (no stray newlines)"""
    hunt = default_hunt(query="index=test sourcetype=test", query_prefix="", query_suffix="")
    assert hunt.query == "index=test sourcetype=test"


# ---------------------------------------------------------------------------
# tests for Jinja2 interpolation of the hunt name field
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_name_jinja_plain_name_unchanged(monkeypatch):
    """plain (non-jinja) names render through unchanged — regression check"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="static name",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert len(submissions) == 1
    assert submissions[0].root.description == "static name"


@pytest.mark.unit
def test_name_jinja_per_event_no_group(monkeypatch):
    """jinja name interpolates per-event when group_by is None"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="dns lookup of {{ query }} from {{ src }}",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "query": "evil.com"},
        {"src": "5.6.7.8", "query": "bad.org"},
    ])
    assert len(submissions) == 2
    descriptions = sorted(s.root.description for s in submissions)
    assert descriptions == [
        "dns lookup of bad.org from 5.6.7.8",
        "dns lookup of evil.com from 1.2.3.4",
    ]


@pytest.mark.unit
def test_name_jinja_with_group_by_field(monkeypatch):
    """jinja name + group_by=<field> still gets the ': <group_value> (N events)' suffix"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="lookup of {{ query }}",
        group_by="src",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "query": "evil.com"},
        {"src": "1.2.3.4", "query": "evil.com"},
        {"src": "5.6.7.8", "query": "bad.org"},
    ])
    assert len(submissions) == 2
    descriptions = sorted(s.root.description for s in submissions)
    assert descriptions == [
        "lookup of bad.org: 5.6.7.8 (1 event)",
        "lookup of evil.com: 1.2.3.4 (2 events)",
    ]


@pytest.mark.unit
def test_name_jinja_with_group_by_all(monkeypatch):
    """jinja name + group_by=ALL renders from the first event and gets the count suffix only"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="hunt for {{ tag }}",
        group_by="ALL",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "tag": "first"},
        {"src": "5.6.7.8", "tag": "second"},
    ])
    assert len(submissions) == 1
    assert submissions[0].root.description == "hunt for first (2 events)"


@pytest.mark.unit
def test_name_jinja_with_description_field(monkeypatch):
    """jinja name + description_field still appends ': <description_field_value>'"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="hunt for {{ src }}",
        group_by=None,
        description_field="alert_title",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([
        {"src": "1.2.3.4", "alert_title": "Suspicious Login"},
    ])
    assert len(submissions) == 1
    assert submissions[0].root.description == "hunt for 1.2.3.4: Suspicious Login"


@pytest.mark.unit
def test_name_jinja_missing_field_renders_empty(monkeypatch):
    """missing fields referenced in the name template render as empty (permissive mode)"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="lookup of [{{ no_such_field }}] from {{ src }}",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert len(submissions) == 1
    assert submissions[0].root.description == "lookup of [] from 1.2.3.4"


@pytest.mark.unit
def test_name_jinja_syntax_error_falls_back_to_raw(monkeypatch, caplog):
    """a malformed jinja template falls back to the raw config name and logs a warning"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    raw_name = "broken {{ unterminated"
    hunt = default_hunt(
        manager=MockManager(),
        name=raw_name,
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    with caplog.at_level(logging.WARNING):
        submissions = hunt.process_query_results([{"src": "1.2.3.4"}])

    assert len(submissions) == 1
    assert submissions[0].root.description == raw_name
    assert any("falling back to raw name" in rec.message for rec in caplog.records)


@pytest.mark.unit
def test_name_jinja_signature_id_display_value_matches(monkeypatch):
    """signature_id observable display_value uses the same rendered name"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    hunt = default_hunt(
        manager=MockManager(),
        name="hunt for {{ src }}",
        group_by=None,
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
    )

    submissions = hunt.process_query_results([{"src": "1.2.3.4"}])
    assert len(submissions) == 1
    sig = next(o for o in submissions[0].root.observables if o.type == F_SIGNATURE_ID)
    assert sig._display_value == "hunt for 1.2.3.4"


@pytest.mark.unit
def test_create_root_analysis_pivot_links_pair_same_field(monkeypatch, tmpdir):
    """pivot_link url+text referencing the same multi-valued field stay paired."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="pivot_pair_test",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        pivot_links=[{
            "url": "https://example.com/?q={{ app }}",
            "text": "{{ app }} info",
        }],
    )
    root = hunt.create_root_analysis({"app": ["incomplete", "not-applicable"]})

    assert len(root.pivot_links) == 2
    pairs = sorted((p.url, p.text) for p in root.pivot_links)
    assert pairs == [
        ("https://example.com/?q=incomplete", "incomplete info"),
        ("https://example.com/?q=not-applicable", "not-applicable info"),
    ]


@pytest.mark.unit
def test_create_root_analysis_skips_unresolved_pivot_links(monkeypatch, tmpdir):
    """pivot_links with unresolved ${...} in url or text are dropped."""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="pivot_unresolved_test",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        pivot_links=[
            {"url": "https://example.com/alerts/{{ alert_id }}", "text": "Alert"},
            {"url": "https://example.com/investigations/{{ investigation_id }}", "text": "Investigation"},
            {"url": "https://example.com/case", "text": "{{ case_name }}"},
        ],
    )

    # only alert_id is present — the other two pivots have unresolved fields
    root = hunt.create_root_analysis({"alert_id": "abc123"})
    assert len(root.pivot_links) == 1
    assert root.pivot_links[0].url == "https://example.com/alerts/abc123"
    assert root.pivot_links[0].text == "Alert"

    # with all fields populated, every pivot is attached
    root = hunt.create_root_analysis({
        "alert_id": "abc123",
        "investigation_id": "inv456",
        "case_name": "Important Case",
    })
    urls = sorted(p.url for p in root.pivot_links)
    assert urls == [
        "https://example.com/alerts/abc123",
        "https://example.com/case",
        "https://example.com/investigations/inv456",
    ]


@pytest.mark.unit
def test_create_root_analysis_skips_unresolved_playbook_url(monkeypatch, tmpdir):
    """playbook_url with unresolved {{ }} is not written to the alert extensions."""
    import saq.collectors.hunter.query_hunter
    from saq.analysis.root import KEY_PLAYBOOK_URL
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="playbook_unresolved_test",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        playbook_url="https://playbooks.example.com/{{ playbook_id }}",
    )

    # field missing — playbook_url is omitted from extensions
    root = hunt.create_root_analysis({})
    assert KEY_PLAYBOOK_URL not in root.extensions

    # field present — playbook_url is set
    root = hunt.create_root_analysis({"playbook_id": "pb42"})
    assert root.extensions[KEY_PLAYBOOK_URL] == "https://playbooks.example.com/pb42"


@pytest.mark.unit
def test_create_root_analysis_records_transaction_id(monkeypatch, tmpdir):
    """the transaction id of the hunt execution is recorded on the root so the resulting
    alert can be correlated back to the log lines for that run"""
    import saq.collectors.hunter.query_hunter
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="transaction_id_test",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
    )

    with transaction_id("known-transaction-id"):
        root = hunt.create_root_analysis({})

    assert root.transaction_id == "known-transaction-id"


@pytest.mark.unit
def test_create_root_analysis_skips_default_transaction_id(monkeypatch, tmpdir):
    """running outside of a transaction context leaves the transaction id off of the root
    rather than recording the meaningless all-zeros sentinel"""
    import saq.collectors.hunter.query_hunter
    from saq.analysis.root import KEY_TRANSACTION_ID
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)
    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "get_temp_dir", lambda: str(tmpdir))

    hunt = default_hunt(
        manager=MockManager(),
        name="transaction_id_default_test",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
    )

    with transaction_id(DEFAULT_TRANSACTION_ID):
        root = hunt.create_root_analysis({})

    assert KEY_TRANSACTION_ID not in root.extensions
    assert root.transaction_id is None


def test_process_query_results_correlate_capture_and_replay(monkeypatch):
    """A correlate query's results are captured on a live run (exposed via
    hunt.correlate_query_results) and replayed offline when _correlate_replay_results
    is seeded, so the data source is never hit."""
    import saq.collectors.hunter.query_hunter
    from saq.collectors.hunter.correlation.registry import (
        QuerySource,
        clear_query_sources,
        register_query_source,
    )
    from saq.collectors.hunter.correlation.schema import CorrelateConfig

    monkeypatch.setattr(saq.collectors.hunter.query_hunter, "local_time", mock_local_time)

    class _Source(QuerySource):
        default_time_field = "_time"
        default_time_format = "iso8601"

        def __init__(self, results):
            self.results = results
            self.calls = []

        def execute_query(self, query, start_time, end_time, timeout, source_options=None):
            self.calls.append(query)
            return list(self.results)

    correlate = CorrelateConfig.model_validate({
        "logic": [
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "property_type": "list",
                    "command": {
                        "type": "query",
                        "source": "test_source",
                        "query": "search host={{ _event.host }}",
                        "time_range": {"before": "1h", "after": "1h"},
                    },
                },
            },
        ],
    })

    input_events = [{"src": "1.2.3.4", "host": "web1", "_time": "2024-06-01T11:00:00+00:00"}]

    clear_query_sources()
    try:
        # --- live run: capture ---
        source = _Source(results=[{"found": True}])
        register_query_source("test_source", source)
        hunt = default_hunt(
            manager=MockManager(),
            name="capture",
            analysis_mode=ANALYSIS_MODE_CORRELATION,
            group_by=None,
            observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
            correlate=correlate,
        )
        hunt.process_query_results([dict(e) for e in input_events])

        assert len(source.calls) == 1
        assert source.calls[0] == "search host=web1"
        captured = hunt.correlate_query_results
        assert captured["version"] == 1
        assert captured["queries"] == [
            {"source": "test_source", "query": "search host=web1", "results": [{"found": True}]},
        ]

        # --- replay run: offline, no live query ---
        replay_source = _Source(results=[{"should": "not be used"}])
        clear_query_sources()
        register_query_source("test_source", replay_source)
        hunt2 = default_hunt(
            manager=MockManager(),
            name="replay",
            analysis_mode=ANALYSIS_MODE_CORRELATION,
            group_by=None,
            observable_mapping=[ObservableMapping(fields=["src"], type="ip")],
            correlate=correlate,
        )
        hunt2._correlate_replay_results = captured["queries"]
        submissions = hunt2.process_query_results([dict(e) for e in input_events])

        assert len(replay_source.calls) == 0  # fully offline
        assert submissions is not None and len(submissions) == 1
    finally:
        clear_query_sources()


# ============================================================
# signature attribution (hunt-emitted detection point + git commit) tests
# ============================================================

import subprocess as _subprocess
from saq.configuration.schema import HuntRuleDirConfig
from saq.signatures import SIGNATURE_VERSION_UNKNOWN


def _init_hunt_git_repo(path):
    """init a git repo at path with one commit, returns the HEAD sha"""
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    _subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
    with open(os.path.join(str(path), ".keep"), "w") as fp:
        fp.write("x")
    _subprocess.run(["git", "-C", str(path), "add", "."], check=True, capture_output=True, env=env)
    _subprocess.run(["git", "-C", str(path), "commit", "-m", "init"], check=True, capture_output=True, env=env)
    out = _subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    return out.stdout.strip()


@pytest.mark.unit
def test_hunt_rule_dirs_schema_accepts_dict_and_rejects_string():
    from pydantic import ValidationError
    # dict form parses, git_dir optional
    cfg = HuntTypeConfig(name="t", python_module="m", python_class="c",
                         rule_dirs=[{"rule_dir": "x", "git_dir": "y"}], update_frequency=60)
    assert cfg.rule_dirs[0].rule_dir == "x"
    assert cfg.rule_dirs[0].git_dir == "y"
    cfg = HuntTypeConfig(name="t", python_module="m", python_class="c",
                         rule_dirs=[{"rule_dir": "x"}], update_frequency=60)
    assert cfg.rule_dirs[0].git_dir is None
    # bare string is rejected (no back-compat)
    with pytest.raises(ValidationError):
        HuntTypeConfig(name="t", python_module="m", python_class="c",
                       rule_dirs=["x"], update_frequency=60)


@pytest.mark.unit
def test_hunt_create_root_analysis_emits_detection_point():
    hunt = default_hunt()
    hunt.signature_version = "abc123commit"
    root = hunt.create_root_analysis({"field1": "v"})
    dps = root.all_detection_points
    assert len(dps) == 1
    assert dps[0].signature_uuid == hunt.uuid
    assert dps[0].signature_version == "abc123commit"


@pytest.mark.unit
def test_hunt_create_root_analysis_no_detection_point_in_non_correlation_mode():
    hunt = default_hunt(analysis_mode=ANALYSIS_MODE_HTTP)
    root = hunt.create_root_analysis({"field1": "v"})
    assert len(root.all_detection_points) == 0
    # the submission still has the configured mode and is not promoted to an alert
    assert root.analysis_mode == ANALYSIS_MODE_HTTP


@pytest.mark.unit
def test_hunt_create_root_analysis_unknown_version_by_default():
    hunt = default_hunt()
    # signature_version defaults to SIGNATURE_VERSION_UNKNOWN until the manager stamps it
    root = hunt.create_root_analysis({"field1": "v"})
    dps = root.all_detection_points
    assert len(dps) == 1
    assert dps[0].signature_version == SIGNATURE_VERSION_UNKNOWN


@pytest.mark.integration
def test_hunt_manager_stamps_signature_version_from_git_dir(manager_kwargs, rules_dir):
    # the rules_dir IS inside a git repo whose git_dir we configure
    sha = _init_hunt_git_repo(rules_dir)
    manager_kwargs["rule_dirs"] = [HuntRuleDirConfig(rule_dir=rules_dir, git_dir=rules_dir)]
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) > 0
    for hunt in manager.hunts:
        assert hunt.signature_version == sha


@pytest.mark.integration
def test_hunt_manager_unknown_version_without_git_dir(manager_kwargs, rules_dir):
    manager_kwargs["rule_dirs"] = [HuntRuleDirConfig(rule_dir=rules_dir)]
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config()
    assert len(manager.hunts) > 0
    for hunt in manager.hunts:
        assert hunt.signature_version == SIGNATURE_VERSION_UNKNOWN
