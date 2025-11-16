import datetime
from unittest.mock import Mock, patch
import pytest

from saq.constants import F_EMAIL_SUBJECT
from saq.analysis import RootAnalysis
from saq.modules.api_analysis import AnalysisDelay
from saq.modules.splunk import SplunkAPIAnalyzer, SplunkAPIAnalysis
from tests.saq.mock_datetime import MOCK_NOW


class MockSplunk:
    """Mock Splunk client that doesn't require actual connection."""

    def __init__(self, *args, **kwargs):
        # don't call parent __init__ to avoid connection attempt
        self.dispatch_state = None
        self.start_time = None
        self.running_start_time = None
        self.end_time = None

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
        analyzer = SplunkAPIAnalyzer(context=test_context)
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
        analyzer = SplunkAPIAnalyzer(context=test_context)
        analyzer.target_query = 'hello'
        analyzer.analysis = SplunkAPIAnalysis()

        # create initial mock job
        mock_job = Mock()
        mock_job.name = "0"
        analyzer.analysis.search_id = mock_job

        # test completed query
        result = analyzer.execute_query()
        assert result == 'hello'
        assert analyzer.analysis.search_id.name == "1"

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
        analyzer = SplunkAPIAnalyzer(context=test_context)
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
        analyzer = SplunkAPIAnalyzer(context=test_context)
        analyzer.target_query_base = '<O_VALUE>'
        analyzer.analysis = SplunkAPIAnalysis()
        analyzer.build_target_query(observable, source_event_time=datetime.datetime.now())

        assert analyzer.target_query == 'Hello, \\"World\\"'
