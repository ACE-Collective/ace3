import datetime
import logging
from unittest.mock import Mock

import pytest

from saq.analysis import RootAnalysis
from saq.constants import F_IP, AnalysisExecutionResult
from saq.modules.api_analysis import AnalysisDelay, BaseAPIAnalysis, BaseAPIAnalyzer, BaseAPIAnalyzerConfig
from saq.util import create_timedelta
from tests.saq.test_util import create_test_context


class _Analyzer(BaseAPIAnalyzer):
    """Answers each query from the results (or exception) it is given."""

    def __init__(self, *args, results=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.results = results
        self.queries = []
        self.processed = []
        self.finalized = []

    def execute_query(self):
        self.queries.append(self.target_query)
        if isinstance(self.results, Exception):
            raise self.results
        return self.results

    def process_query_results(self, query_results, analysis, observable):
        self.processed.append(query_results)

    def process_finalize(self, analysis, observable):
        self.finalized.append(observable)


def _config(**kwargs):
    kwargs.setdefault("query", "search ip=<O_VALUE> type=<O_TYPE>")
    return BaseAPIAnalyzerConfig(
        name="test_api_analyzer", python_module="tests.saq.modules.test_api_analysis", python_class="_Analyzer",
        enabled=True, question="Was it seen?", summary="Test API", api_name="test_api", **kwargs)


@pytest.fixture
def delayed_analysis():
    return Mock(**{"delay_analysis.return_value": True})


@pytest.fixture
def root():
    root = RootAnalysis()
    root.event_time = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    return root


def _analyzer(root, delayed_analysis, results=None, analyzer_class=_Analyzer, **config):
    context = create_test_context(root=root, delayed_analysis_interface=delayed_analysis)
    return analyzer_class(context=context, config=_config(**config), results=results)


@pytest.mark.unit
def test_generated_analysis_type_defaults_to_base_analysis(root, delayed_analysis):
    # it used to be a plain method, so a subclass that didn't override it handed the engine a bound method
    analyzer = _analyzer(root, delayed_analysis, results=[])
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    assert analyzer.generated_analysis_type is BaseAPIAnalysis
    assert isinstance(analyzer.create_analysis(observable), BaseAPIAnalysis)


@pytest.mark.unit
def test_execute_analysis_processes_results(root, delayed_analysis):
    analyzer = _analyzer(root, delayed_analysis, results=[{"src": "10.0.0.2"}, {"src": "10.0.0.3"}])
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(BaseAPIAnalysis)
    assert analysis.query == "search ip=10.0.0.1 type=ip"
    assert analysis.question == "Was it seen?"
    assert analysis.query_error is None
    assert analyzer.processed == [[{"src": "10.0.0.2"}, {"src": "10.0.0.3"}]]
    assert analyzer.finalized == [observable]
    assert analysis.generate_summary() == "Test API: (2 results)"


@pytest.mark.unit
def test_execute_analysis_summary_details(root, delayed_analysis):
    analyzer = _analyzer(root, delayed_analysis, results={"user": "jdoe"},
                         summary_details=[{"content": "user {{ user }}", "header": "Users"}])
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    analyzer.execute_analysis(observable)

    assert [(d.header, d.content) for d in root.summary_details] == [("Users", "user jdoe")]


@pytest.mark.unit
def test_execute_analysis_query_error(root, delayed_analysis, caplog):
    analyzer = _analyzer(root, delayed_analysis, results=RuntimeError("connection refused"))
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(BaseAPIAnalysis)
    assert analysis.query_error == "connection refused"
    assert analysis.query_results is None
    assert analyzer.processed == []
    assert analysis.generate_summary() == "Test API: ERROR: connection refused"
    assert any(r.levelno == logging.ERROR and "connection refused" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_correlation_delay_delays_before_querying(root, delayed_analysis):
    analyzer = _analyzer(root, delayed_analysis, results=[], correlation_delay="00:00:05:00")
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.INCOMPLETE

    assert analyzer.queries == []
    assert delayed_analysis.delay_analysis.call_args.kwargs["seconds"] == 300


@pytest.mark.unit
def test_async_query_delays_until_timeout(root, delayed_analysis, caplog):
    analyzer = _analyzer(root, delayed_analysis, results=AnalysisDelay(), query_timeout=60, async_delay=7)
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.INCOMPLETE
    assert delayed_analysis.delay_analysis.call_args.kwargs["seconds"] == 7

    # the engine calls continue_analysis when the delay expires, and the query is not built again
    analysis = observable.get_analysis(BaseAPIAnalysis)
    analysis.query = "search ip=10.0.0.1 already built"
    analysis.query_start -= 61
    assert analyzer.continue_analysis(observable, analysis) == AnalysisExecutionResult.COMPLETED

    assert analyzer.queries == ["search ip=10.0.0.1 type=ip", "search ip=10.0.0.1 already built"]
    assert analysis.query_error == "timed out"
    assert analysis.query_results is None
    assert any(r.levelno == logging.WARNING and "query timed out" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_continue_analysis_return_analysis(root, delayed_analysis):
    analyzer = _analyzer(root, delayed_analysis, results=[])
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    analysis = analyzer.execute_analysis(observable, return_analysis=True)

    assert isinstance(analysis, BaseAPIAnalysis)
    assert analysis.query_results == []
    # no results, nothing to say
    assert analysis.generate_summary() is None


@pytest.mark.unit
@pytest.mark.parametrize("results,summary", [
    ({"events": []}, None),
    ({"events": [{}, {}, {}]}, "Test API: (3 results)"),
    ({"a": 1}, "Test API: (1 results)"),
    ([], None),
])
def test_generate_summary(results, summary):
    analysis = BaseAPIAnalysis()
    analysis.query_summary = "Test API"
    analysis.query_results = results

    assert analysis.generate_summary() == summary


@pytest.mark.unit
def test_generate_summary_without_results_or_error():
    analysis = BaseAPIAnalysis()
    analysis.query_summary = "Test API"

    assert analysis.generate_summary() == "Test API: Test API (no results or error??)"
    assert analysis.jinja_template_path == "analysis/api_analysis.html"


@pytest.mark.unit
def test_configured_durations_override_api_defaults(root, delayed_analysis):
    defaults = _analyzer(root, delayed_analysis)
    configured = _analyzer(root, delayed_analysis, wide_duration_before="00:02:00:00", wide_duration_after="00:03:00:00",
                           narrow_duration_before="00:00:02:00", narrow_duration_after="00:00:03:00",
                           max_result_count=5, query_timeout=11, async_delay=13,
                           time_ranges={"LOOKBACK": {"duration_before": "01:00:00:00"}, "EMPTY": {}})

    assert configured.wide_duration_before == create_timedelta("00:02:00:00")
    assert configured.wide_duration_after == create_timedelta("00:03:00:00")
    assert configured.narrow_duration_before == create_timedelta("00:00:02:00")
    assert configured.narrow_duration_after == create_timedelta("00:00:03:00")
    assert configured.max_result_count == 5
    assert configured.query_timeout == 11
    assert configured.async_delay_seconds == 13
    assert configured.additional_time_ranges == {
        "LOOKBACK": {"duration_before": datetime.timedelta(days=1), "duration_after": datetime.timedelta(0)},
        "EMPTY": {"duration_before": datetime.timedelta(0), "duration_after": datetime.timedelta(0)},
    }

    assert defaults.wide_duration_before == create_timedelta(defaults.api_defaults.wide_duration_before)
    assert defaults.query_timeout == defaults.api_defaults.query_timeout
    assert defaults.async_delay_seconds == defaults.api_defaults.async_delay
    assert defaults.additional_time_ranges == {}


@pytest.mark.unit
def test_verify_environment(root, delayed_analysis, tmp_path):
    analyzer = _analyzer(root, delayed_analysis)
    analyzer.config.query = None
    with pytest.raises(RuntimeError, match="missing query or query_path"):
        analyzer.verify_environment()

    query_path = tmp_path / "ip.query"
    query_path.write_text("search ip=<O_VALUE>")
    analyzer = _analyzer(root, delayed_analysis, query=None, query_path=str(query_path))
    assert analyzer.target_query_base == "search ip=<O_VALUE>"
    analyzer.verify_environment()

    query_path.unlink()
    with pytest.raises(RuntimeError, match="ip.query"):
        analyzer.verify_environment()


@pytest.mark.unit
def test_build_target_query_observable_attributes(root, delayed_analysis):
    analyzer = _analyzer(root, delayed_analysis, query="ip=<observable.value> type=<observable.type>")
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    analyzer.build_target_query(observable)

    assert analyzer.target_query == "ip=10.0.0.1 type=ip"


@pytest.mark.unit
def test_build_target_query_multiple_values(root, delayed_analysis):
    analyzer = _analyzer(root, delayed_analysis, query="src=<O_VALUE1> dst=<O_VALUE2>")
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    with pytest.raises(ValueError, match="mismatched number of values"):
        analyzer.build_target_query(observable)

    analyzer.multi_values = ["10.0.0.1", "10.0.0.2"]
    analyzer.build_target_query(observable)
    assert analyzer.target_query == "src=10.0.0.1 dst=10.0.0.2"


@pytest.mark.unit
def test_build_target_query_json(root, delayed_analysis):
    analyzer = _analyzer(root, delayed_analysis, query='{"term": {"ip": "<O_VALUE>"}}')
    analyzer.json_query = True
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    analyzer.build_target_query(observable)
    assert analyzer.target_query == {"term": {"ip": "10.0.0.1"}}

    analyzer.target_query_base = '{"term": <O_VALUE>}'
    with pytest.raises(ValueError, match="not valid JSON") as error:
        analyzer.build_target_query(observable)
    assert error.value.__cause__ is not None


@pytest.mark.unit
def test_build_target_query_time_ranges_without_event_time(delayed_analysis, caplog):
    root = RootAnalysis()
    analyzer = _analyzer(root, delayed_analysis, query="ip=<O_VALUE> <LOOKBACK>",
                         time_ranges={"LOOKBACK": {"duration_before": "00:01:00:00"}})
    analyzer.fill_additional_timespecs = Mock()
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")
    root.event_time = None

    analyzer.build_target_query(observable)

    (start, stop), = analyzer.fill_additional_timespecs.call_args.args[0].values()
    assert stop - start == datetime.timedelta(hours=1)
    assert any(r.levelno == logging.ERROR and "event_time is None" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_build_target_query_time_ranges_default_hook(root, delayed_analysis):
    # a subclass that doesn't fill named timespecs used to raise AttributeError when time_ranges were configured
    analyzer = _analyzer(root, delayed_analysis, query="ip=<O_VALUE> <LOOKBACK>",
                         time_ranges={"LOOKBACK": {"duration_before": "00:01:00:00"}})
    observable = root.add_observable_by_spec(F_IP, "10.0.0.1")

    analyzer.build_target_query(observable)

    assert analyzer.target_query == "ip=10.0.0.1 <LOOKBACK>"
