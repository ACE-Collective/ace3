from datetime import UTC, datetime
import json
import os
from queue import Queue
import shutil
import pytest

from saq.analysis.root import RootAnalysis
from saq.collectors.hunter import HuntManager, HunterCollector
from saq.collectors.hunter.splunk_hunter import SplunkHunt
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, F_FILE, F_FILE_NAME, F_HUNT
from saq.environment import get_data_dir
from saq.util.time import create_timedelta

SPLUNK_URI = 'https://localhost:8089'
SPLUNK_ALT_URI = 'https://localhost:8091'

# TODO move test hunts to datadir

@pytest.fixture
def rules_dir(datadir) -> str:
    temp_rules_dir = datadir / "test_rules"
    shutil.copytree("hunts/test/splunk", temp_rules_dir)
    return str(temp_rules_dir)

class TestSplunkHunter(HunterCollector):
    __test__ = False

    def update(self):
        pass

    def cleanup(self):
        pass

@pytest.fixture
def manager_kwargs(rules_dir):
    return { 
        'submission_queue': Queue(),
        'hunt_type': 'splunk',
        'rule_dirs': [ rules_dir, ],
        'hunt_cls': SplunkHunt,
        'concurrency_limit': 1,
        'persistence_dir': os.path.join(get_data_dir(), get_config()['collection']['persistence_dir']),
        'update_frequency': 60,
        'config': {}
    }

@pytest.fixture
def manager_kwargs_alt(rules_dir):
    return { 
        'submission_queue': Queue(),
        'hunt_type': 'splunk_alt',
        'rule_dirs': [ rules_dir, ],
        'hunt_cls': SplunkHunt,
        'concurrency_limit': 1,
        'persistence_dir': os.path.join(get_data_dir(), get_config()['collection']['persistence_dir']),
        'update_frequency': 60,
        'config': {'splunk_config': 'splunk_alt'}
    }

@pytest.fixture(autouse=True, scope="function")
def setup(rules_dir):
    #ips_txt = 'hunts/test/splunk/ips.txt'
    #with open(ips_txt, 'w') as fp:
        #fp.write('1.1.1.1\n')

    get_config()['splunk']['uri'] = SPLUNK_URI

@pytest.mark.integration
def test_load_hunt_ini(manager_kwargs):
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_1')
    assert len(manager.hunts) == 1
    
    hunt = manager.get_hunt_by_name('query_test_1')
    assert hunt
    assert hunt.enabled
    assert hunt.name == 'query_test_1'
    assert hunt.description == 'Query Test Description 1'
    assert hunt.frequency == create_timedelta('00:01:00')
    assert hunt.tags == ['tag1', 'tag2']
    assert hunt.time_range == create_timedelta('00:01:00')
    assert hunt.max_time_range == create_timedelta('01:00:00')
    assert hunt.offset == create_timedelta('00:05:00')
    assert hunt.full_coverage
    assert hunt.group_by == 'field1'
    assert hunt.query == 'index=proxy {time_spec} src_ip=1.1.1.1\n'
    assert hunt.use_index_time
    assert len(hunt.observable_mapping) == 2
    assert hunt.observable_mapping[0].fields == ['src_ip']
    assert hunt.observable_mapping[0].type == 'ipv4'
    assert hunt.observable_mapping[0].time
    assert hunt.observable_mapping[1].fields == ['dst_ip']
    assert hunt.observable_mapping[1].type == 'ipv4'
    assert hunt.observable_mapping[1].time
    assert hunt.namespace_app is None
    assert hunt.namespace_user is None

    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'test_app_context')
    assert len(manager.hunts) == 1

    hunt = manager.get_hunt_by_name('test_app_context')
    assert hunt.namespace_app == 'app'
    assert hunt.namespace_user == 'user'

@pytest.mark.skip(reason="missing file")
@pytest.mark.integration
def test_no_timespec(manager_kwargs):
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_no_timespec')
    assert len(manager.hunts) == 1
    hunt = manager.get_hunt_by_name('query_test_no_timespec')
    assert hunt is not None
    assert hunt.query == '{time_spec} index=proxy src_ip=1.1.1.1\n'

@pytest.mark.integration
def test_load_hunt_with_includes(manager_kwargs):
    ips_txt = 'hunts/test/splunk/ips.txt'
    with open(ips_txt, 'w') as fp:
        fp.write('1.1.1.1\n')

    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_includes')
    hunt = manager.get_hunt_by_name('query_test_includes')
    assert hunt
    # same as above except that ip address comes from a different file
    assert hunt.query == 'index=proxy {time_spec} src_ip=1.1.1.1\n'

    # and then change it and it should have a different value 
    with open(ips_txt, 'a') as fp:
        fp.write('1.1.1.2\n')

    assert hunt.query, 'index=proxy {time_spec} src_ip=1.1.1.1\n1.1.1.2\n'

    os.remove(ips_txt)

@pytest.mark.integration
def test_splunk_query(manager_kwargs, datadir):
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'Test Splunk Query')
    assert len(manager.hunts) == 1
    hunt = manager.get_hunt_by_name('Test Splunk Query')
    assert hunt

    with open(str(datadir / 'hunts/splunk/test_output.json'), 'r') as fp:
        query_results = json.load(fp)

    result = hunt.execute(unit_test_query_results=query_results)
    assert isinstance(result, list)
    assert len(result) == 4
    for submission in result:
        assert submission.root.analysis_mode == ANALYSIS_MODE_CORRELATION
        assert isinstance(submission.root.details, dict)
        assert "events" in submission.root.details
        assert isinstance(submission.root.details["events"], list)
        assert all([isinstance(_, dict) for _ in submission.root.details["events"]])
        assert submission.root.get_observables_by_type(F_FILE) == []
        for tag in ["tag1", "tag2"]:
            assert submission.root.has_tag(tag)

        assert submission.root.tool_instance == get_config()[hunt.splunk_config]['uri']
        assert submission.root.alert_type == 'hunter - splunk - test'

        if submission.root.description == 'Test Splunk Query: 29380 (3 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 36, tzinfo=UTC)
            assert isinstance(submission.root, RootAnalysis)
            assert submission.root.has_observable_by_spec(F_HUNT, "Test Splunk Query")
            assert submission.root.has_observable_by_spec(F_FILE_NAME, "__init__.py")
        elif submission.root.description == 'Test Splunk Query: 29385 (2 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 37, tzinfo=UTC)
            assert submission.root.has_observable_by_spec(F_HUNT, "Test Splunk Query")
            assert submission.root.has_observable_by_spec(F_FILE_NAME, "__init__.py")
        elif submission.root.description == 'Test Splunk Query: 29375 (2 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 36, tzinfo=UTC)
            assert submission.root.has_observable_by_spec(F_HUNT, "Test Splunk Query")
            assert submission.root.has_observable_by_spec(F_FILE_NAME, "__init__.py")
        elif submission.root.description == 'Test Splunk Query: 31185 (93 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 22, tzinfo=UTC)
            assert submission.root.has_observable_by_spec(F_HUNT, "Test Splunk Query")
            assert submission.root.has_observable_by_spec(F_FILE_NAME, "__init__.py")
        else:
            raise RuntimeError(f"invalid description: {submission.description}")

@pytest.mark.skip(reason="missing file")
@pytest.mark.integration
def test_splunk_query_observable_id_mapping(manager_kwargs, datadir):
    class ObservableStub:
        def __init__(self, type, value):
            self.type = type
            self.value = value

    mock_db_observables = {
        '1': ObservableStub('test_type', 'test_value')
    }

    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'Test Splunk Observable ID Mapping')
    assert len(manager.hunts) == 1
    hunt = manager.get_hunt_by_name('Test Splunk Observable ID Mapping')
    assert hunt

    with open(str(datadir / 'hunts/splunk/test_output_2.json'), 'r') as fp:
        query_results = json.load(fp)

    result = hunt.execute(unit_test_query_results=query_results, mock_db_observables=mock_db_observables)
    assert isinstance(result, list)
    assert len(result) == 4
    for submission in result:
        assert submission.root.has_observable_by_spec(F_HUNT, 'Test Splunk Observable ID Mapping')
        assert submission.root.has_observable_by_spec("test_type", "test_value")

@pytest.mark.skip(reason="missing file")
@pytest.mark.integration
def test_splunk_query_multiple_observable_id_mapping(manager_kwargs, datadir):
    class ObservableStub:
        def __init__(self, type, value):
            self.type = type
            self.value = value

    mock_db_observables = {
        '1234': ObservableStub('test_type1', 'test_value1'),
        '5678': ObservableStub('test_type2', 'test_value2'),
    }

    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'Test Splunk Observable ID Mapping')
    assert len(manager.hunts) == 1
    hunt = manager.get_hunt_by_name('Test Splunk Observable ID Mapping')
    assert hunt

    with open(str(datadir / 'hunts/splunk/test_list_output.json'), 'r') as fp:
        query_results = json.load(fp)

    result = hunt.execute(unit_test_query_results=query_results, mock_db_observables=mock_db_observables)
    assert isinstance(result, list)
    assert len(result) == 1
    for submission in result:
        assert submission.observables == [
            {'type': 'hunt', 'value': 'Test Splunk Observable ID Mapping'},
            {'type': 'test_type1', 'value': 'test_value1'},
            {'type': 'test_type2', 'value': 'test_value2'}
        ]

@pytest.mark.integration
def test_splunk_hunt_types(manager_kwargs):
    manager1 = HuntManager(**manager_kwargs)
    manager1.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_1')

    # even though there are multiple splunk hunts in the config
    # only 1 gets loaded because the other is type splunk_alt
    assert len(manager1.hunts) == 1
    splunk_hunt = manager1.hunts[0]
    assert splunk_hunt.type == 'splunk'

@pytest.fixture
def alt_setup(rules_dir):
        shutil.rmtree(rules_dir)
        shutil.copytree('hunts/test/splunk', rules_dir)
        
        splunk_sections = [_ for _ in get_config().sections() if _.startswith('splunk')]
        for splunk_section in splunk_sections:
            del get_config()[splunk_section]

        get_config().add_section('splunk')
        get_config()['splunk']['uri'] = SPLUNK_URI
        get_config()['splunk']['timezone'] = 'GMT'

        get_config().add_section('splunk_alt')
        get_config()['splunk_alt']['uri'] = SPLUNK_ALT_URI
        get_config()['splunk_alt']['timezone'] = 'GMT'

        get_config().add_section('hunt_type_splunk_alt')
        s = get_config()['hunt_type_splunk_alt']
        s['module'] = 'saq.collectors.splunk_hunter'
        s['class'] = 'SplunkHunter'
        s['rule_dirs'] = rules_dir
        s['concurrency_limit'] = '1'
        s['splunk_config'] = 'splunk_alt'

@pytest.mark.integration
def test_splunk_hunt_host_config(alt_setup, manager_kwargs, manager_kwargs_alt):
    manager = HuntManager(**manager_kwargs_alt)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    splunk_alt_hunt = manager.hunts[0]
    assert splunk_alt_hunt.tool_instance == SPLUNK_ALT_URI
    
    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_1')
    splunk_hunt = manager.hunts[0]
    assert splunk_hunt.tool_instance == SPLUNK_URI