import datetime
from unittest.mock import Mock, patch

import pytest
import pytz
from pydantic import ValidationError

from saq.analysis import RootAnalysis
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_SPLUNK_API, F_EMAIL_SUBJECT, F_IP
from saq.modules.api_analysis import AnalysisDelay
from saq.modules.splunk import (
    SplunkAPIAnalysis,
    SplunkAPIAnalyzer,
    SplunkAPIAnalyzerConfig,
)
from saq.observables.mapping import FieldsMode, ObservableMapping
from saq.query.config import PivotLinkConfig
from saq.splunk import SplunkQueryObject, encode_splunk_query_link, splunk_gui_path
from tests.saq.mock_datetime import MOCK_NOW


def _pivot_link_config(**pivot_links_kwargs):
    """Build a minimal SplunkAPIAnalyzerConfig carrying the given pivot_links."""
    return SplunkAPIAnalyzerConfig(
        name="test_splunk",
        python_module="saq.modules.splunk",
        python_class="SplunkAPIAnalyzer",
        enabled=True,
        question="Test question?",
        summary="Test summary",
        api_name="test_api",
        query="index=test",
        observable_mapping=[],
        **pivot_links_kwargs,
    )


class MockJobsDict:
    """Mock for Splunk client.jobs with dict-like access."""
    def __init__(self):
        self._jobs = {}

    def __getitem__(self, name):
        if name not in self._jobs:
            raise KeyError(name)
        return self._jobs[name]

    def add(self, job):
        self._jobs[job.name] = job


class MockSplunk:
    """Mock Splunk client that doesn't require actual connection."""

    def __init__(self, *args, **kwargs):
        # don't call parent __init__ to avoid connection attempt
        self.dispatch_state = None
        self.start_time = None
        self.running_start_time = None
        self.end_time = None
        # Mock client with jobs dict for job lookup
        self.client = Mock()
        self.client.jobs = MockJobsDict()
        self.host = "splunk.local"
        self.gui_path = splunk_gui_path()

    def add_mock_job(self, job):
        """Add a job to the mock jobs dict for lookup."""
        self.client.jobs.add(job)

    # building the link is local code, so the real one runs
    encoded_query_link = SplunkQueryObject.encoded_query_link

    def query_async(self, query, job=None, limit=1000, start=None, end=None, use_index_time=False, timeout=None):
        # create a mock job with an incrementing name
        mock_job = Mock()
        if job is None:
            mock_job.name = "1"
        else:
            mock_job.name = str(int(job.name) + 1)
        return mock_job, query

    def reset_search_status(self, dispatch_state=None, start_time=None, running_start_time=None, end_time=None):
        self.dispatch_state = dispatch_state
        self.start_time = start_time
        self.running_start_time = running_start_time
        self.end_time = end_time


@pytest.mark.unit
def test_splunk_api_analyzer_search_url(test_context):
    # mock SplunkClient to return our mock
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        # init analyzer
        analyzer = SplunkAPIAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_SPLUNK_API))
        analyzer.target_query = 'hello'

        # test no param
        result = analyzer.search_url()
        assert result == 'https://splunk.local/en-US/app/search/search?q=search+hello'

        # test with param
        result = analyzer.search_url('foo')
        assert result == 'https://splunk.local/en-US/app/search/search?q=search+foo'


@pytest.mark.unit
def test_splunk_api_analyzer_execute_query(test_context):
    # mock SplunkClient to return our mock
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        # init
        analyzer = SplunkAPIAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_SPLUNK_API))
        analyzer.target_query = 'hello'
        analyzer.analysis = SplunkAPIAnalysis()

        # create initial mock job and add it to mock splunk's job dict
        mock_job = Mock()
        mock_job.name = "0"
        mock_splunk.add_mock_job(mock_job)
        analyzer.analysis.search_id = mock_job  # This now stores "0" (string)

        # test completed query
        result = analyzer.execute_query()
        assert result == 'hello'
        # search_id now stores the job name as a string, not the Job object
        assert analyzer.analysis.search_id == "1"

        # test delay
        analyzer.target_query = None
        with pytest.raises(AnalysisDelay):
            result = analyzer.execute_query()


@pytest.mark.unit
def test_splunk_api_analyzer_fill_timespec(test_context):
    # mock SplunkClient to return our mock
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        # init
        analyzer = SplunkAPIAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_SPLUNK_API))
        analyzer.target_query = 'hello <O_TIMESPEC> world'
        analyzer.analysis = SplunkAPIAnalysis()

        # test fill timespec
        analyzer.fill_target_query_timespec(MOCK_NOW, MOCK_NOW)

        # verify
        assert analyzer.target_query == 'hello _index_earliest = 11/11/2017:07:36:01 _index_latest = 11/11/2017:07:36:01 world'
        # the link is to the query with <O_TIMESPEC> removed, over the same time range
        tz = pytz.timezone(analyzer.timezone)
        assert analyzer.analysis.details['gui_link'].startswith('https://splunk.local/en-US/app/search/search?q=search+hello++world&earliest=')
        assert analyzer.analysis.details['gui_link'] == encode_splunk_query_link(
            'splunk.local', splunk_gui_path(), 'hello  world', MOCK_NOW.astimezone(tz), MOCK_NOW.astimezone(tz))
        assert analyzer.analysis.details['gui_link_label'] == 'Open in Splunk'


@pytest.mark.unit
def test_splunk_api_analyzer_escape_value(test_context):
    # mock SplunkClient to return our mock
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        observable = RootAnalysis().add_observable_by_spec(F_EMAIL_SUBJECT, 'Hello, "World"')
        analyzer = SplunkAPIAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_SPLUNK_API))
        analyzer.target_query_base = '<O_VALUE>'
        analyzer.analysis = SplunkAPIAnalysis()
        analyzer.build_target_query(observable, source_event_time=datetime.datetime.now())

        assert analyzer.target_query == 'Hello, \\"World\\"'


@pytest.mark.unit
def test_api_observable_mapping_model():
    """Test ObservableMapping Pydantic model validation."""
    # Test with single field
    mapping = ObservableMapping(field="src_ip", type="ipv4")
    assert mapping.get_fields() == ["src_ip"]
    assert mapping.tags == []
    assert mapping.directives == []

    # Test with multiple fields
    mapping = ObservableMapping(fields=["user", "username"], type="user")
    assert mapping.get_fields() == ["user", "username"]

    # Test with tags and directives
    mapping = ObservableMapping(
        field="src_ip",
        type="ipv4",
        tags=["external", "suspicious"],
        directives=["analyze_ip"],
        time=True,
        ignored_values=[r"0\.0\.0\.0", r"127\.0\.0\.1"],
        display_type="custom_ip",
        display_value="Source IP"
    )
    assert mapping.tags == ["external", "suspicious"]
    assert mapping.directives == ["analyze_ip"]
    assert mapping.time is True
    assert mapping.ignored_values == [r"0\.0\.0\.0", r"127\.0\.0\.1"]
    assert mapping.display_type == "custom_ip"
    assert mapping.display_value == "Source IP"

    # Test validation error when neither field nor fields is specified
    with pytest.raises(ValueError, match="Either 'field' or 'fields' must be specified"):
        ObservableMapping(type="ipv4")


@pytest.mark.unit
def test_extract_result_observables_with_tags(test_context):
    """Test that extract_result_observables applies tags and directives."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        # Create a config with observable mapping that includes tags
        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    field="src_ip",
                    type="ipv4",
                    tags=["external", "from_splunk"],
                    directives=["analyze"],
                    time=True
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        # Create a mock analysis
        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # Mock result from Splunk
        result = {"src_ip": "10.0.0.1", "other_field": "ignored"}
        result_time = datetime.datetime.now(datetime.timezone.utc)

        # Extract observables
        analyzer.extract_result_observables(analysis, result, observable, result_time)

        # Verify observable was created with tags and directives
        assert len(analysis.observables) == 1
        new_obs = analysis.observables[0]
        assert new_obs.value == "10.0.0.1"
        assert "external" in new_obs.tags
        assert "from_splunk" in new_obs.tags
        assert "analyze" in new_obs.directives
        assert new_obs.time == result_time


@pytest.mark.unit
def test_extract_result_observables_multiple_fields(test_context):
    """Test that multiple fields mapping uses first field's value when all fields are present."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    fields=["user", "username", "account"],
                    type="user"
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # All fields present - first field's value is used
        result = {"user": "jdoe", "username": "jsmith", "account": "admin"}

        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 1
        assert analysis.observables[0].value == "jdoe"


@pytest.mark.unit
def test_extract_result_observables_ignored_values(test_context):
    """Test that ignored values are skipped."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    field="src_ip",
                    type="ipv4",
                    ignored_values=[r"0\.0\.0\.0", r"127\.0\.0\.1"]
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # Value is in ignored list
        result = {"src_ip": "127.0.0.1"}
        analyzer.extract_result_observables(analysis, result, observable)

        # No observable should be created
        assert len(analysis.observables) == 0

        # Now with a valid value
        result = {"src_ip": "10.0.0.1"}
        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 1
        assert analysis.observables[0].value == "10.0.0.1"


@pytest.mark.unit
def test_extract_result_observables_ignored_values_regex(test_context):
    """Test that ignored_values supports regex patterns via re.fullmatch()."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    field="src_ip",
                    type="ipv4",
                    ignored_values=[r"10\.0\..*"]
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # 10.0.1.1 should be ignored by the regex pattern
        result = {"src_ip": "10.0.1.1"}
        analyzer.extract_result_observables(analysis, result, observable)
        assert len(analysis.observables) == 0

        # 10.0.255.3 should also be ignored
        result = {"src_ip": "10.0.255.3"}
        analyzer.extract_result_observables(analysis, result, observable)
        assert len(analysis.observables) == 0

        # 192.168.1.1 should NOT be ignored
        result = {"src_ip": "192.168.1.1"}
        analyzer.extract_result_observables(analysis, result, observable)
        assert len(analysis.observables) == 1
        assert analysis.observables[0].value == "192.168.1.1"


@pytest.mark.unit
def test_extract_result_observables_fields_mode_any(test_context):
    """Test that fields_mode=any creates a separate observable for each present field."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    fields=["src_ip", "dst_ip"],
                    type="ipv4",
                    fields_mode=FieldsMode.ANY,
                    tags=["from_splunk"]
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        result = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 2
        values = sorted([o.value for o in analysis.observables])
        assert values == ["10.0.0.1", "10.0.0.2"]
        # verify tags applied to both
        for obs in analysis.observables:
            assert "from_splunk" in obs.tags


@pytest.mark.unit
def test_extract_result_observables_fields_mode_any_partial(test_context):
    """Test that fields_mode=any creates observables only for present fields."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    fields=["src_ip", "dst_ip"],
                    type="ipv4",
                    fields_mode=FieldsMode.ANY,
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # only src_ip is present
        result = {"src_ip": "10.0.0.1", "other": "value"}
        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 1
        assert analysis.observables[0].value == "10.0.0.1"


@pytest.mark.unit
def test_extract_result_observables_fields_mode_all(test_context):
    """Test that fields_mode=all uses first non-null value (default behavior)."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    fields=["src_ip", "dst_ip"],
                    type="ipv4",
                    fields_mode=FieldsMode.ALL,
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # both fields present - should create observable from first field
        result = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 1
        assert analysis.observables[0].value == "10.0.0.1"


@pytest.mark.unit
def test_extract_result_observables_fields_mode_all_missing(test_context):
    """Test that fields_mode=all creates no observable when some fields are missing."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    fields=["src_ip", "dst_ip"],
                    type="ipv4",
                    fields_mode=FieldsMode.ALL,
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # only src_ip present - ALL mode requires all fields, so no observable
        result = {"src_ip": "10.0.0.1"}
        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 0


@pytest.mark.unit
def test_extract_result_observables_fields_mode_all_no_match(test_context):
    """Test that fields_mode=all creates no observable when no fields are present."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test",
            observable_mapping=[
                ObservableMapping(
                    fields=["src_ip", "dst_ip"],
                    type="ipv4",
                    fields_mode=FieldsMode.ALL,
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # no matching fields present - should NOT create observable
        result = {"other": "value"}
        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 0


@pytest.mark.unit
def test_api_observable_mapping_fields_mode_validation():
    """Test that ObservableMapping accepts valid fields_mode values."""
    # Default is ALL
    mapping = ObservableMapping(field="src_ip", type="ipv4")
    assert mapping.fields_mode == FieldsMode.ALL

    # Explicit ANY
    mapping = ObservableMapping(field="src_ip", type="ipv4", fields_mode=FieldsMode.ANY)
    assert mapping.fields_mode == FieldsMode.ANY

    # Explicit ALL
    mapping = ObservableMapping(field="src_ip", type="ipv4", fields_mode=FieldsMode.ALL)
    assert mapping.fields_mode == FieldsMode.ALL

    # String values should also work (Pydantic coercion)
    mapping = ObservableMapping(field="src_ip", type="ipv4", fields_mode="any")
    assert mapping.fields_mode == FieldsMode.ANY

    mapping = ObservableMapping(field="src_ip", type="ipv4", fields_mode="all")
    assert mapping.fields_mode == FieldsMode.ALL


@pytest.mark.unit
def test_splunk_api_analyzer_o_timespec_requires_observable_time(test_context):
    """Test that <O_TIMESPEC> raises ValueError when observable has no time."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test <O_TIMESPEC>",
            use_index_time=False,
            observable_mapping=[],
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)
        analyzer.analysis = SplunkAPIAnalysis()

        # observable without time
        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")

        with pytest.raises(ValueError, match="O_TIMESPEC.*no time"):
            analyzer.build_target_query(observable, source_event_time=datetime.datetime.now(datetime.timezone.utc))


@pytest.mark.unit
def test_splunk_api_analyzer_o_timespec_uses_narrow_durations(test_context):
    """Test that <O_TIMESPEC> always uses narrow durations when observable has time."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="index=test <O_TIMESPEC>",
            use_index_time=False,
            # set wide and narrow to different values to verify narrow is used
            wide_duration_before="48:00:00",
            wide_duration_after="48:00:00",
            narrow_duration_before="01:00:00",
            narrow_duration_after="01:00:00",
            observable_mapping=[],
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)
        analyzer.analysis = SplunkAPIAnalysis()

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        observable.time = MOCK_NOW

        analyzer.build_target_query(observable)

        # narrow is 1 hour, so earliest should be MOCK_NOW - 1h, latest MOCK_NOW + 1h
        # MOCK_NOW is 11/11/2017:07:36:01
        # -1h = 11/11/2017:06:36:01, +1h = 11/11/2017:08:36:01
        assert 'earliest = 11/11/2017:06:36:01' in analyzer.target_query
        assert 'latest = 11/11/2017:08:36:01' in analyzer.target_query
        # verify wide (48h) was NOT used
        assert '11/09/2017' not in analyzer.target_query
        assert '11/13/2017' not in analyzer.target_query


@pytest.mark.unit
def test_splunk_api_analyzer_fill_additional_timespecs(test_context):
    """Test that fill_additional_timespecs replaces TIMESPEC tokens in target_query."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        analyzer = SplunkAPIAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_SPLUNK_API))
        analyzer.target_query = 'hello <TIMESPEC2> world <TIMESPEC3> end'

        additional_times = {
            'TIMESPEC2': (MOCK_NOW, MOCK_NOW),
            'TIMESPEC3': (MOCK_NOW, MOCK_NOW),
        }
        analyzer.fill_additional_timespecs(additional_times)

        # use_index_time is True for the test config
        assert '<TIMESPEC2>' not in analyzer.target_query
        assert '<TIMESPEC3>' not in analyzer.target_query
        assert '_index_earliest = 11/11/2017:07:36:01' in analyzer.target_query
        assert '_index_latest = 11/11/2017:07:36:01' in analyzer.target_query


@pytest.mark.unit
def test_splunk_api_analyzer_fill_additional_timespecs_event_time(test_context):
    """Test that fill_additional_timespecs uses event time format, not index time, when use_index_time=False."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk = MockSplunk()
        mock_splunk_client.return_value = mock_splunk

        config = SplunkAPIAnalyzerConfig(
            name="test_splunk",
            python_module="saq.modules.splunk",
            python_class="SplunkAPIAnalyzer",
            enabled=True,
            question="Test question?",
            summary="Test summary",
            api_name="test_api",
            query="hello <TIMESPEC2> world",
            use_index_time=False,
            observable_mapping=[],
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)
        analyzer.target_query = 'hello <TIMESPEC2> world'

        additional_times = {
            'TIMESPEC2': (MOCK_NOW, MOCK_NOW),
        }
        analyzer.fill_additional_timespecs(additional_times)

        assert '<TIMESPEC2>' not in analyzer.target_query
        assert 'earliest = 11/11/2017:07:36:01' in analyzer.target_query
        assert 'latest = 11/11/2017:07:36:01' in analyzer.target_query
        assert '_index_' not in analyzer.target_query


@pytest.mark.unit
def test_pivot_link_config_invalid_target():
    """An invalid target falls back to 'root' rather than raising."""
    pl = PivotLinkConfig(url="https://example.com", text="link", target="bogus")
    assert pl.target == "root"

    # valid targets are preserved
    assert PivotLinkConfig(url="u", text="t", target="analysis").target == "analysis"
    # default is root
    assert PivotLinkConfig(url="u", text="t").target == "root"


@pytest.mark.unit
def test_process_pivot_links_basic(test_context):
    """A single pivot_link with scalar fields produces one link on the root alert (the default target)."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://splunk.example.com/search?q={{ src_ip }}",
            "text": "Pivot on {{ src_ip }}",
            "icon": "search",
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{"src_ip": "10.0.0.1"}]

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        assert len(root_links) == 1
        assert root_links[0].url == "https://splunk.example.com/search?q=10.0.0.1"
        assert root_links[0].text == "Pivot on 10.0.0.1"
        assert root_links[0].icon == "search"
        # nothing attached to the analysis node
        assert len(analysis.pivot_links) == 0


@pytest.mark.unit
def test_process_pivot_links_target_analysis(test_context):
    """A pivot_link with target='analysis' attaches to the analysis node, not the root alert."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://splunk.example.com/search?q={{ src_ip }}",
            "text": "Pivot on {{ src_ip }}",
            "target": "analysis",
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{"src_ip": "10.0.0.1"}]

        analyzer.process_pivot_links(analysis)

        assert len(analyzer.get_root().pivot_links) == 0
        assert len(analysis.pivot_links) == 1
        assert analysis.pivot_links[0].url == "https://splunk.example.com/search?q=10.0.0.1"
        assert analysis.pivot_links[0].text == "Pivot on 10.0.0.1"
        assert analysis.pivot_links[0].icon is None


@pytest.mark.unit
def test_process_pivot_links_multi_valued_field_pairs(test_context):
    """url and text referencing the same multi-valued field stay paired per value."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://example.com/?q={{ app }}",
            "text": "{{ app }} info",
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{"app": ["incomplete", "not-applicable"]}]

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        assert len(root_links) == 2
        pairs = sorted((p.url, p.text) for p in root_links)
        assert pairs == [
            ("https://example.com/?q=incomplete", "incomplete info"),
            ("https://example.com/?q=not-applicable", "not-applicable info"),
        ]


@pytest.mark.unit
def test_process_pivot_links_skips_undefined(test_context):
    """A pivot_link referencing a field absent from the event is skipped, not raised."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[
            {"url": "https://example.com/{{ present }}", "text": "Present"},
            {"url": "https://example.com/{{ missing }}", "text": "Missing"},
        ])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{"present": "abc123"}]

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        assert len(root_links) == 1
        assert root_links[0].url == "https://example.com/abc123"
        assert root_links[0].text == "Present"


@pytest.mark.unit
def test_process_pivot_links_skips_empty_values(test_context):
    """A rendered link with an empty url or text is skipped."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[
            {"url": "https://example.com/{{ host }}", "text": "{{ label }}"},
        ])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        # label renders empty -> link skipped
        analysis.query_results = [{"host": "server1", "label": ""}]

        analyzer.process_pivot_links(analysis)

        assert len(analyzer.get_root().pivot_links) == 0
        assert len(analysis.pivot_links) == 0


@pytest.mark.unit
def test_process_pivot_links_dedup(test_context):
    """Identical rendered links are deduplicated; links differing in any part are kept."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        # static link (no template vars) rendered against multiple events
        config = _pivot_link_config(pivot_links=[
            {"url": "https://example.com/static", "text": "Static"},
            {"url": "https://example.com/{{ host }}", "text": "Host link"},
        ])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [
            {"host": "server1"},
            {"host": "server1"},  # duplicate of the above
            {"host": "server2"},
        ]

        analyzer.process_pivot_links(analysis)

        urls = sorted(p.url for p in analyzer.get_root().pivot_links)
        assert urls == [
            "https://example.com/server1",
            "https://example.com/server2",
            "https://example.com/static",
        ]


@pytest.mark.unit
def test_process_pivot_links_dedup_against_existing(test_context):
    """A link already on the target (e.g. from a prior module run) is not re-added."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://example.com/{{ host }}",
            "text": "{{ host }}",
            "target": "root",
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        # simulate a prior run having already added this link to the root alert
        analyzer.get_root().add_pivot_link("https://example.com/server1", None, "server1")

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{"host": "server1"}, {"host": "server2"}]

        analyzer.process_pivot_links(analysis)

        urls = sorted(p.url for p in analyzer.get_root().pivot_links)
        assert urls == ["https://example.com/server1", "https://example.com/server2"]


@pytest.mark.unit
def test_process_pivot_links_root_and_analysis_independent_dedup(test_context):
    """The same rendered tuple targeting both root and analysis lands on each."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[
            {"url": "https://example.com/x", "text": "Link", "target": "analysis"},
            {"url": "https://example.com/x", "text": "Link", "target": "root"},
        ])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{}]

        analyzer.process_pivot_links(analysis)

        assert len(analysis.pivot_links) == 1
        assert len(analyzer.get_root().pivot_links) == 1


@pytest.mark.unit
def test_process_pivot_links_empty_config(test_context):
    """With no pivot_links configured, process_pivot_links is a no-op."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        analyzer = SplunkAPIAnalyzer(context=test_context, config=_pivot_link_config())

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{"src_ip": "10.0.0.1"}]

        analyzer.process_pivot_links(analysis)

        assert len(analysis.pivot_links) == 0
        assert len(analyzer.get_root().pivot_links) == 0


@pytest.mark.unit
def test_process_pivot_links_query_results_dict(test_context):
    """query_results as a single dict is normalized to a one-event list."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://example.com/{{ host }}",
            "text": "{{ host }}",
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = {"host": "server1"}

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        assert len(root_links) == 1
        assert root_links[0].url == "https://example.com/server1"


@pytest.mark.unit
def test_pivot_link_config_negative_limit_raises():
    """A negative `limit` is a loud config-load error; 0 and positive are accepted."""
    with pytest.raises(ValidationError):
        PivotLinkConfig(url="u", text="t", limit=-1)

    assert PivotLinkConfig(url="u", text="t").limit is None
    assert PivotLinkConfig(url="u", text="t", limit=0).limit == 0
    assert PivotLinkConfig(url="u", text="t", limit=5).limit == 5


@pytest.mark.unit
def test_pivot_link_config_overflow_without_limit_tolerated():
    """`overflow` without `limit` is tolerated (logged) — the overflow link just never fires."""
    pl = PivotLinkConfig(url="u", text="t", overflow={"url": "ou", "text": "ot"})
    assert pl.overflow is not None
    assert pl.overflow.url == "ou"
    assert pl.limit is None


@pytest.mark.unit
def test_process_pivot_links_limit_caps_links(test_context):
    """`limit` caps the number of emitted links, preserving query-result order."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://example.com/{{ id }}",
            "text": "Task {{ id }}",
            "limit": 2,
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [{"id": str(i)} for i in range(1, 6)]

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        assert len(root_links) == 2
        assert [link.url for link in root_links] == [
            "https://example.com/1",
            "https://example.com/2",
        ]


@pytest.mark.unit
def test_process_pivot_links_overflow_skipped_when_not_truncated(test_context):
    """With results at or under `limit`, every link is shown and no overflow link is added."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://example.com/{{ id }}",
            "text": "Task {{ id }}",
            "limit": 5,
            "overflow": {"url": "{{ endpoint }}$tsf.do", "text": "More"},
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [
            {"id": str(i), "endpoint": "https://snow.example.com/"} for i in range(1, 4)
        ]

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        assert len(root_links) == 3
        assert all(link.text != "More" for link in root_links)


@pytest.mark.unit
def test_process_pivot_links_overflow_emitted_when_truncated(test_context):
    """When `limit` truncates the result set, a single overflow link is appended."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://example.com/{{ id }}",
            "text": "Task {{ id }}",
            "icon": "snow",
            "limit": 2,
            "overflow": {
                "url": "{{ endpoint }}$tsf.do?sysparm_search={{ term | urlencode }}",
                "text": "More ServiceNow results ({{ overflow_count }} more)",
            },
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [
            {"id": str(i), "endpoint": "https://snow.example.com/", "term": "jdoe@acme.com"}
            for i in range(1, 6)
        ]

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        # 2 capped per-row links + 1 overflow link
        assert len(root_links) == 3
        assert [link.url for link in root_links[:2]] == [
            "https://example.com/1",
            "https://example.com/2",
        ]
        overflow = root_links[2]
        assert overflow.url == "https://snow.example.com/$tsf.do?sysparm_search=jdoe%40acme.com"
        assert overflow.text == "More ServiceNow results (3 more)"
        # overflow inherits the parent pivot link's icon when it specifies none
        assert overflow.icon == "snow"


@pytest.mark.unit
def test_process_pivot_links_overflow_icon_override(test_context):
    """An overflow entry with its own `icon` uses it rather than inheriting the parent's."""
    with patch("saq.modules.splunk.SplunkClient") as mock_splunk_client:
        mock_splunk_client.return_value = MockSplunk()

        config = _pivot_link_config(pivot_links=[{
            "url": "https://example.com/{{ id }}",
            "text": "Task {{ id }}",
            "icon": "parent-icon",
            "limit": 1,
            "overflow": {
                "url": "{{ endpoint }}/more",
                "text": "More",
                "icon": "overflow-icon",
            },
        }])
        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IP, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)
        analysis.query_results = [
            {"id": "1", "endpoint": "https://snow.example.com"},
            {"id": "2", "endpoint": "https://snow.example.com"},
        ]

        analyzer.process_pivot_links(analysis)

        root_links = analyzer.get_root().pivot_links
        assert len(root_links) == 2
        assert root_links[0].icon == "parent-icon"
        assert root_links[1].text == "More"
        assert root_links[1].icon == "overflow-icon"
