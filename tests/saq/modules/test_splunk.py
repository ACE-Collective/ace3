import datetime
from unittest.mock import Mock, patch
import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_SPLUNK_API, F_EMAIL_SUBJECT, F_IPV4
from saq.analysis import RootAnalysis
from saq.modules.api_analysis import AnalysisDelay, APIObservableMapping
from saq.modules.splunk import SplunkAPIAnalyzer, SplunkAPIAnalysis, SplunkAPIAnalyzerConfig
from tests.saq.mock_datetime import MOCK_NOW


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

    def add_mock_job(self, job):
        """Add a job to the mock jobs dict for lookup."""
        self.client.jobs.add(job)

    def encoded_query_link(self, query, start_time=None, end_time=None):
        return query + ' world'

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
        assert result == 'hello world'

        # test with param
        result = analyzer.search_url('foo')
        assert result == 'foo world'


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
        # the MockSplunk appends ' world' to the query, and the query passed is 'hello  ' (with <O_TIMESPEC> removed)
        assert analyzer.analysis.details['gui_link'] == 'hello  world world'


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
    """Test APIObservableMapping Pydantic model validation."""
    # Test with single field
    mapping = APIObservableMapping(field="src_ip", type="ipv4")
    assert mapping.get_fields() == ["src_ip"]
    assert mapping.tags == []
    assert mapping.directives == []

    # Test with multiple fields
    mapping = APIObservableMapping(fields=["user", "username"], type="user")
    assert mapping.get_fields() == ["user", "username"]

    # Test with tags and directives
    mapping = APIObservableMapping(
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
        APIObservableMapping(type="ipv4")


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
                APIObservableMapping(
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
        observable = root.add_observable_by_spec(F_IPV4, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # Mock result from Splunk
        result = {"src_ip": "10.0.0.1", "other_field": "ignored"}
        result_time = datetime.datetime.now()

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
    """Test that multiple fields mapping uses first non-null value."""
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
                APIObservableMapping(
                    fields=["user", "username", "account"],
                    type="user"
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IPV4, "1.2.3.4")
        analysis = analyzer.create_analysis(observable)

        # First field is null, second has value
        result = {"user": None, "username": "jsmith", "account": "admin"}

        analyzer.extract_result_observables(analysis, result, observable)

        assert len(analysis.observables) == 1
        assert analysis.observables[0].value == "jsmith"


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
                APIObservableMapping(
                    field="src_ip",
                    type="ipv4",
                    ignored_values=[r"0\.0\.0\.0", r"127\.0\.0\.1"]
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IPV4, "1.2.3.4")
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
                APIObservableMapping(
                    field="src_ip",
                    type="ipv4",
                    ignored_values=[r"10\.0\..*"]
                )
            ]
        )

        analyzer = SplunkAPIAnalyzer(context=test_context, config=config)

        root = RootAnalysis()
        observable = root.add_observable_by_spec(F_IPV4, "1.2.3.4")
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
