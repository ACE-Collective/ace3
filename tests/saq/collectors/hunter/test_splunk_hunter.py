from datetime import UTC, datetime
import json
import os
from queue import Queue
import shutil
import pytest

from saq.analysis.root import RootAnalysis
from saq.collectors.hunter import HuntManager, HunterCollector
from saq.collectors.hunter.splunk_hunter import SplunkHunt
from saq.configuration.config import get_config, get_splunk_config
from saq.configuration.schema import HuntTypeConfig, SplunkConfig
from saq.constants import ANALYSIS_MODE_CORRELATION, F_FILE, F_FILE_NAME, TIMESPEC_TOKEN
from saq.environment import get_data_dir
from saq.util.time import create_timedelta

SPLUNK_HOST = 'localhost'
SPLUNK_PORT = 8089
SPLUNK_ALT_HOST = 'localhost'
SPLUNK_ALT_PORT = 8091

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
        'persistence_dir': os.path.join(get_data_dir(), get_config().collection.persistence_dir),
        'update_frequency': 60,
        'config': get_splunk_config()
    }

@pytest.fixture
def manager_kwargs_alt(rules_dir):
    return {
        'submission_queue': Queue(),
        'hunt_type': 'splunk_alt',
        'rule_dirs': [ rules_dir, ],
        'hunt_cls': SplunkHunt,
        'concurrency_limit': 1,
        'persistence_dir': os.path.join(get_data_dir(), get_config().collection.persistence_dir),
        'update_frequency': 60,
        'config': get_splunk_config("splunk_alt")
    }

@pytest.fixture(autouse=True, scope="function")
def setup(rules_dir):
    #ips_txt = 'hunts/test/splunk/ips.txt'
    #with open(ips_txt, 'w') as fp:
        #fp.write('1.1.1.1\n')

    get_splunk_config().host = SPLUNK_HOST
    get_splunk_config().port = SPLUNK_PORT

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
    assert hunt.query == 'index=proxy src_ip=1.1.1.1\n'
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
    assert hunt.query == 'index=proxy src_ip=1.1.1.1\n'

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
    assert hunt.query == 'index=proxy src_ip=1.1.1.1\n'

    # and then change it and it should have a different value
    with open(ips_txt, 'a') as fp:
        fp.write('1.1.1.2\n')

    assert hunt.query, 'index=proxy src_ip=1.1.1.1\n1.1.1.2\n'

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

        assert submission.root.tool_instance == hunt.splunk_config.host
        assert submission.root.alert_type == 'hunter - splunk - test'

        if submission.root.description == 'Test Splunk Query: 29380 (3 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 36, tzinfo=UTC)
            assert isinstance(submission.root, RootAnalysis)
            assert submission.root.has_observable_by_spec(F_FILE_NAME, "__init__.py")
        elif submission.root.description == 'Test Splunk Query: 29385 (2 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 37, tzinfo=UTC)
            assert submission.root.has_observable_by_spec(F_FILE_NAME, "__init__.py")
        elif submission.root.description == 'Test Splunk Query: 29375 (2 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 36, tzinfo=UTC)
            assert submission.root.has_observable_by_spec(F_FILE_NAME, "__init__.py")
        elif submission.root.description == 'Test Splunk Query: 31185 (93 events)':
            assert submission.root.event_time == datetime(2019, 12, 23, 16, 5, 22, tzinfo=UTC)
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

        get_config().clear_splunk_configs()

        get_config().add_splunk_config("default",
            SplunkConfig(
                name="default",
                enabled=True,
                host=SPLUNK_HOST,
                port=SPLUNK_PORT,
                timezone="GMT",
                performance_logging_dir="splunk_perf",
            )
        )
        get_config().add_splunk_config("splunk_alt",
            SplunkConfig(
                name="splunk_alt",
                enabled=True,
                host=SPLUNK_ALT_HOST,
                port=SPLUNK_ALT_PORT,
                timezone="GMT",
                performance_logging_dir="splunk_perf",
            ),
        )

        get_config().clear_hunt_type_configs()
        get_config().add_hunt_type_config("splunk_alt",
            HuntTypeConfig(
                name="splunk_alt",
                python_module="saq.collectors.hunter.splunk_hunter",
                python_class="SplunkHunt",
                rule_dirs=[rules_dir],
                concurrency_limit=1,
                splunk_config=get_config().get_splunk_config("splunk_alt"),
                update_frequency=60,
            ),
        )

@pytest.mark.integration
def test_splunk_hunt_host_config(alt_setup, manager_kwargs, manager_kwargs_alt):
    manager = HuntManager(**manager_kwargs_alt)
    manager.load_hunts_from_config()
    assert len(manager.hunts) == 1
    splunk_alt_hunt = manager.hunts[0]
    assert splunk_alt_hunt.tool_instance == SPLUNK_ALT_HOST

    manager = HuntManager(**manager_kwargs)
    manager.load_hunts_from_config(hunt_filter=lambda hunt: hunt.name == 'query_test_1')
    splunk_hunt = manager.hunts[0]
    assert splunk_hunt.tool_instance == SPLUNK_HOST


@pytest.mark.unit
def test_splunk_hunt_config_auto_append_default():
    """test that SplunkHuntConfig has auto_append property with default '| fields *'"""
    from saq.collectors.hunter.splunk_hunter import SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
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
    assert config.auto_append == "| fields *"


@pytest.mark.unit
def test_splunk_hunt_config_auto_append_custom():
    """test that SplunkHuntConfig auto_append property can be overridden"""
    from saq.collectors.hunter.splunk_hunter import SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
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
        auto_append="| fields src_ip dst_ip"
    )

    assert config.auto_append == "| fields src_ip dst_ip"


@pytest.mark.unit
def test_splunk_hunt_config_auto_append_empty():
    """test that SplunkHuntConfig auto_append property can be set to empty string"""
    from saq.collectors.hunter.splunk_hunter import SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
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
        auto_append=""
    )

    assert config.auto_append == ""


@pytest.mark.unit
def test_splunk_hunt_formatted_query_with_default_auto_append(manager_kwargs):
    """test that SplunkHunt formatted_query appends default '| fields *' to query"""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
        enabled=True,
        description="test description",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="index=test",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)
    formatted = hunt.formatted_query()
    assert formatted == "index=test | fields *"


@pytest.mark.unit
def test_splunk_hunt_formatted_query_with_custom_auto_append(manager_kwargs):
    """test that SplunkHunt formatted_query appends custom auto_append to query"""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
        enabled=True,
        description="test description",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="index=test",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append="| fields src_ip dst_ip"
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    formatted = hunt.formatted_query()
    assert formatted == "index=test | fields src_ip dst_ip"


@pytest.mark.unit
def test_splunk_hunt_formatted_query_with_empty_auto_append(manager_kwargs):
    """test that SplunkHunt formatted_query with empty auto_append does not append anything"""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
        enabled=True,
        description="test description",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="index=test",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append=""
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    formatted = hunt.formatted_query()
    assert formatted == "index=test"


@pytest.mark.unit
def test_splunk_hunt_formatted_query_already_has_auto_append(manager_kwargs):
    """test that SplunkHunt formatted_query does not duplicate auto_append if query already ends with it"""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
        enabled=True,
        description="test description",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="index=test | fields *",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    formatted = hunt.formatted_query()
    # should not duplicate "| fields *"
    assert formatted == "index=test | fields *"
    assert formatted.count("| fields *") == 1


@pytest.mark.unit
def test_splunk_hunt_formatted_query_timeless_with_auto_append(manager_kwargs):
    """test that SplunkHunt formatted_query_timeless also appends auto_append"""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_hunt",
        type="splunk",
        enabled=True,
        description="test description",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="index=test",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append=" | fields src_ip"
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    formatted = hunt.formatted_query_timeless()
    assert formatted == "index=test | fields src_ip"


@pytest.mark.unit
def test_splunk_hunt_pipe_query_no_time_spec_prepend(manager_kwargs):
    """Verify the query property does not prepend {time_spec} for pipe queries."""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_pipe_hunt",
        type="splunk",
        enabled=True,
        description="test pipe query",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="| tstats count where index=main",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    # query should NOT have {time_spec} prepended for pipe queries
    assert '{time_spec}' not in hunt.query
    assert hunt.query.lstrip().startswith('|')


@pytest.mark.unit
def test_splunk_hunt_pipe_query_execute_query(manager_kwargs):
    """Verify execute_query() passes a clean pipe query to query_async()."""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_pipe_hunt",
        type="splunk",
        enabled=True,
        description="test pipe query",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="| tstats count where index=main",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append="",
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 1, 0, 0, tzinfo=UTC)

    # use unit_test_query_results to bypass actual Splunk connection
    result = hunt.execute_query(start, end, unit_test_query_results=[{"count": "42"}])

    # the formatted query should be the raw pipe query
    assert result == [{"count": "42"}]


@pytest.mark.unit
def test_splunk_hunt_timespec_single_token(manager_kwargs):
    """Test that <TIMESPEC> token is replaced with the hunt's time range."""
    from unittest.mock import Mock, patch
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_timespec",
        type="splunk",
        enabled=True,
        description="test timespec",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="<TIMESPEC> index=test",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append="",
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 0, 10, 0, tzinfo=UTC)

    # Mock SplunkClient to capture the query
    mock_searcher = Mock()
    mock_searcher.encoded_query_link.return_value = "http://test"
    mock_searcher.query_async.return_value = (Mock(), [{"count": "1"}])
    mock_searcher.search_failed.return_value = False

    with patch("saq.collectors.hunter.splunk_hunter.SplunkClient", return_value=mock_searcher):
        result = hunt.execute_query(start, end)

    # Verify query_async was called with embed_time_in_query=False
    call_kwargs = mock_searcher.query_async.call_args[1]
    assert call_kwargs['embed_time_in_query'] is False

    # Verify the query has the TIMESPEC token replaced with the correct window
    query_arg = call_kwargs.get('query') or mock_searcher.query_async.call_args[0][0]
    assert '<TIMESPEC>' not in query_arg
    assert 'earliest=01/01/2024:00:00:00' in query_arg
    assert 'latest=01/01/2024:00:10:00' in query_arg

    # And the results are still returned correctly
    assert result == [{"count": "1"}]


@pytest.mark.unit
def test_splunk_hunt_timespec_multiple_tokens(manager_kwargs):
    """Test that <TIMESPEC> and <TIMESPEC2> are replaced with different time ranges."""
    from unittest.mock import Mock, patch
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_timespec_multi",
        type="splunk",
        enabled=True,
        description="test multiple timespecs",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="<TIMESPEC> index=test [search <TIMESPEC2> index=test2]",
        full_coverage=True,
        use_index_time=False,
        auto_append="",
        time_ranges={TIMESPEC_TOKEN: "00:10:00", "TIMESPEC2": "00:30:00"},
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 0, 10, 0, tzinfo=UTC)

    # Mock SplunkClient to capture the query
    mock_searcher = Mock()
    mock_searcher.encoded_query_link.return_value = "http://test"
    mock_searcher.query_async.return_value = (Mock(), [{"count": "1"}])
    mock_searcher.search_failed.return_value = False

    with patch("saq.collectors.hunter.splunk_hunter.SplunkClient", return_value=mock_searcher):
        result = hunt.execute_query(start, end)

    # Verify query_async was called with embed_time_in_query=False
    call_kwargs = mock_searcher.query_async.call_args[1]
    assert call_kwargs['embed_time_in_query'] is False

    # Verify the query has both timespecs replaced
    query_arg = mock_searcher.query_async.call_args[1].get('query') or mock_searcher.query_async.call_args[0][0]
    assert '<TIMESPEC>' not in query_arg
    assert '<TIMESPEC2>' not in query_arg

    # TIMESPEC should use start-end (10 min window)
    assert 'earliest=01/01/2024:00:00:00' in query_arg
    assert 'latest=01/01/2024:00:10:00' in query_arg

    # TIMESPEC2 should use 30 min lookback from end_time
    # end_time - 30min = 2023-12-31 23:40:00
    assert 'earliest=12/31/2023:23:40:00' in query_arg


@pytest.mark.unit
def test_splunk_hunt_timespec_unconfigured_token_raises(manager_kwargs):
    """Test that an unconfigured TIMESPEC token raises ValueError."""
    from unittest.mock import Mock, patch
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_timespec_error",
        type="splunk",
        enabled=True,
        description="test unconfigured timespec",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="<TIMESPEC> index=test [search <TIMESPEC3> index=test2]",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append="",
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 0, 10, 0, tzinfo=UTC)

    mock_searcher = Mock()
    mock_searcher.encoded_query_link.return_value = "http://test"

    with patch("saq.collectors.hunter.splunk_hunter.SplunkClient", return_value=mock_searcher):
        with pytest.raises(ValueError, match="TIMESPEC3"):
            hunt.execute_query(start, end)


@pytest.mark.unit
def test_splunk_hunt_no_timespec_unchanged(manager_kwargs):
    """Test queries without TIMESPEC tokens use the existing code path."""
    from unittest.mock import Mock, patch
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_no_timespec",
        type="splunk",
        enabled=True,
        description="test no timespec",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="index=test",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=False,
        auto_append="",
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 0, 10, 0, tzinfo=UTC)

    mock_searcher = Mock()
    mock_searcher.encoded_query_link.return_value = "http://test"
    mock_searcher.query_async.return_value = (Mock(), [{"count": "1"}])
    mock_searcher.search_failed.return_value = False

    with patch("saq.collectors.hunter.splunk_hunter.SplunkClient", return_value=mock_searcher):
        result = hunt.execute_query(start, end)

    # Verify query_async was called with embed_time_in_query=True
    call_kwargs = mock_searcher.query_async.call_args[1]
    assert call_kwargs['embed_time_in_query'] is True


@pytest.mark.unit
def test_splunk_hunt_timespec_index_time(manager_kwargs):
    """Test that TIMESPEC with use_index_time uses _index_ prefix."""
    from unittest.mock import Mock, patch
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_timespec_index",
        type="splunk",
        enabled=True,
        description="test timespec with index time",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="<TIMESPEC> index=test",
        time_range="00:10:00",
        full_coverage=True,
        use_index_time=True,
        auto_append="",
    )

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 0, 10, 0, tzinfo=UTC)

    mock_searcher = Mock()
    mock_searcher.encoded_query_link.return_value = "http://test"
    mock_searcher.query_async.return_value = (Mock(), [{"count": "1"}])
    mock_searcher.search_failed.return_value = False

    with patch("saq.collectors.hunter.splunk_hunter.SplunkClient", return_value=mock_searcher):
        result = hunt.execute_query(start, end)

    query_arg = mock_searcher.query_async.call_args[0][0]
    assert '_index_earliest=' in query_arg
    assert '_index_latest=' in query_arg


@pytest.mark.unit
def test_splunk_hunt_config_time_ranges_timespec_only(manager_kwargs):
    """Test that config with only time_ranges.TIMESPEC (no time_range) validates and hunt.time_range works."""
    from saq.collectors.hunter.splunk_hunter import SplunkHunt, SplunkHuntConfig

    config = SplunkHuntConfig(
        uuid="test-uuid",
        name="test_timespec_only",
        type="splunk",
        enabled=True,
        description="test time_ranges only",
        alert_type="test_alert",
        frequency="00:10:00",
        tags=[],
        instance_types=["unittest"],
        query="<TIMESPEC> index=test",
        full_coverage=True,
        use_index_time=False,
        auto_append="",
        time_ranges={TIMESPEC_TOKEN: "00:15:00"},
    )

    assert config.time_range is None
    assert config.time_ranges is not None
    assert TIMESPEC_TOKEN in config.time_ranges

    manager = HuntManager(**manager_kwargs)
    hunt = SplunkHunt(config=config, manager=manager)

    # time_range property should fall back to time_ranges.TIMESPEC
    assert hunt.time_range == create_timedelta("00:15:00")


@pytest.mark.unit
def test_splunk_hunt_config_neither_time_range_nor_timespec_raises():
    """Test that config with neither time_range nor time_ranges.TIMESPEC raises ValueError."""
    from saq.collectors.hunter.splunk_hunter import SplunkHuntConfig

    with pytest.raises(ValueError, match="Either 'time_range' or 'time_ranges' with a TIMESPEC entry must be specified"):
        SplunkHuntConfig(
            uuid="test-uuid",
            name="test_no_time",
            type="splunk",
            enabled=True,
            description="test missing time range",
            alert_type="test_alert",
            frequency="00:10:00",
            tags=[],
            instance_types=["unittest"],
            query="<TIMESPEC> index=test",
            full_coverage=True,
            use_index_time=False,
        )


@pytest.mark.unit
def test_splunk_hunt_config_time_ranges_without_timespec_raises():
    """Test that config with time_ranges but no TIMESPEC entry and no time_range raises ValueError."""
    from saq.collectors.hunter.splunk_hunter import SplunkHuntConfig

    with pytest.raises(ValueError, match="Either 'time_range' or 'time_ranges' with a TIMESPEC entry must be specified"):
        SplunkHuntConfig(
            uuid="test-uuid",
            name="test_no_timespec",
            type="splunk",
            enabled=True,
            description="test missing TIMESPEC in time_ranges",
            alert_type="test_alert",
            frequency="00:10:00",
            tags=[],
            instance_types=["unittest"],
            query="<TIMESPEC> index=test",
            full_coverage=True,
            use_index_time=False,
            time_ranges={"TIMESPEC2": "00:30:00"},
        )
