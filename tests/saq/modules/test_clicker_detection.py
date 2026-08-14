import copy
import datetime
from unittest.mock import Mock, patch

import pytest

from saq.analysis import RootAnalysis
from saq.analysis.module_path import MODULE_PATH
from saq.constants import DIRECTIVE_CRAWL, F_EMAIL_ADDRESS, F_FQDN, F_IP, F_URL
from saq.modules.clicker_detection import (
    SplunkClickerDetectionAnalysis,
    SplunkClickerDetectionAnalyzer,
    SplunkClickerDetectionAnalyzerConfig,
)
from saq.signatures.builtin import URL_CLICKER
from tests.saq.modules.test_splunk import MockSplunk

NOW = datetime.datetime.now(datetime.timezone.utc)

# Synthetic rows shaped like MS Defender defender:urlclick logs.
ROW_ALLOWED = {
    "Timestamp": "2026-06-17T12:03:46.6719381Z", "AccountUpn": "clicker@example.com",
    "ActionType": "ClickAllowed", "Url": "https://evil.example/landing",
    "NetworkMessageId": "msg-allowed", "IPAddress": "170.85.13.109",
}
ROW_BLOCKED = {
    "Timestamp": "2026-06-17T12:04:00.0000000Z", "AccountUpn": "blocked@example.com",
    "ActionType": "ClickBlocked", "Url": "https://evil.example/landing",
    "NetworkMessageId": "msg-blocked", "IPAddress": "10.0.0.5",
}
# Synthetic proxy log row (no allowed/blocked signal).
PROXY_ROW = {
    "_time": "2026-06-17T12:05:00Z", "user": "visitor@example.com",
    "url": "https://evil.example/landing", "action": "allowed",
}

SAFELINKS = {
    "observable_types": ["url", "fqdn"],
    "query": 'index=app_defender_hunting sourcetype="urlclick" <O_VALUE> <TIMESPEC>\n'
             '| table Timestamp AccountUpn ActionType Url NetworkMessageId IPAddress',
    "time_ranges": {"TIMESPEC": {"duration_before": "07:00:00:00", "duration_after": "00:01:00:00"}},
    "use_index_time": False,
    "observable_mapping": [
        {"field": "AccountUpn", "type": "email_address", "display_type": "Clicker"},
        {"field": "IPAddress", "type": "ip"},
    ],
    "event_mapping": {"timestamp": "Timestamp", "user": "AccountUpn", "action_type": "ActionType",
                      "url": "Url", "network_message_id": "NetworkMessageId"},
    "on_hit": {"escalate_action_types": ["ClickAllowed"], "add_detection_point": True, "crawl_clicked_url": True},
}
PROXY = {
    "observable_types": ["url", "fqdn"],
    "query": 'index=proxy sourcetype="px" <O_VALUE> <TIMESPEC>\n| table _time user url action',
    "time_ranges": {"TIMESPEC": {"duration_before": "07:00:00:00", "duration_after": "00:01:00:00"}},
    "observable_mapping": [{"field": "user", "type": "email_address", "display_type": "Clicker"}],
    "event_mapping": {"timestamp": "_time", "user": "user", "action_type": "action", "url": "url"},
    "on_hit": {"escalate_on_any": True, "add_detection_point": True, "crawl_clicked_url": True},
}

URL_CONFIG = {"splunk": {"enabled": True, "searches": {"safelinks": copy.deepcopy(SAFELINKS)}}}
MULTI_CONFIG = {"splunk": {"enabled": True, "searches": {"safelinks": copy.deepcopy(SAFELINKS),
                                                          "proxy": copy.deepcopy(PROXY)}}}


class MockMultiSplunk(MockSplunk):
    """Returns preset rows depending on a marker substring in the query, so each named
    search 'finds' its own rows synchronously (no AnalysisDelay)."""
    def __init__(self, rows_by_marker):
        super().__init__()
        self.rows_by_marker = rows_by_marker

    def query_async(self, query, job=None, limit=1000, **kwargs):
        mock_job = Mock()
        mock_job.name = "1"
        for marker, rows in self.rows_by_marker.items():
            if marker in query:
                return mock_job, rows
        return mock_job, []


def _make_analyzer(test_context, clicker_config):
    config = SplunkClickerDetectionAnalyzerConfig(
        name="clicker_detection_splunk", instance="clicker_detection_splunk",
        python_module="saq.modules.clicker_detection", python_class="SplunkClickerDetectionAnalyzer",
        enabled=True, api_name="test_api", question="Did anyone click this?", summary="URL Clicks",
        valid_observable_types=["url", "fqdn"], required_directives=["clicker_detection"], source="splunk",
    )
    analyzer = SplunkClickerDetectionAnalyzer(context=test_context, config=config)
    analyzer._clicker_config = clicker_config
    analyzer._initialized = True  # bypass watch_file/disk load
    return analyzer


def _run(analyzer, observable):
    analysis = analyzer.create_analysis(observable)
    analyzer.continue_analysis(observable, analysis)
    return analysis


@pytest.mark.unit
def test_url_hit_extracts_clickers_and_escalates(test_context):
    splunk = MockMultiSplunk({"app_defender_hunting": [ROW_ALLOWED, ROW_BLOCKED]})
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, URL_CONFIG)
        observable = RootAnalysis().add_observable_by_spec(F_URL, "https://evil.example/landing")
        analysis = _run(analyzer, observable)

        events = analysis.details["clicker_events"]
        assert len(events) == 2
        assert all(e["source"] == "splunk:safelinks" for e in events)

        emails = [o for o in analysis.observables if o.type == F_EMAIL_ADDRESS]
        assert {o.value for o in emails} == {"clicker@example.com", "blocked@example.com"}
        assert all("Clicker" in o.display_type for o in emails)
        assert any(o.type == F_IP for o in analysis.observables)

        # only the ClickAllowed row escalates
        assert analysis.has_detection_points()
        # detection points are attributed to the shared clicker BuiltinSignature
        assert all(dp.signature_uuid == URL_CLICKER.uuid for dp in analysis.detections)
        assert observable.has_directive(DIRECTIVE_CRAWL)

        published = analysis.get_clicker_events()
        assert {e.source for e in published} == {"splunk:safelinks"}
        # the URL column shows the searched observable value for every row
        assert all(e.searched_value == "https://evil.example/landing" for e in published)
        allowed = [e for e in published if e.action_type == "ClickAllowed"][0]
        assert allowed.user == "clicker@example.com"
        assert allowed.portal_url  # per-search search link
        # node-level "Open in Splunk" button is set for the clicker node too
        assert analysis.details["gui_link"]
        assert analysis.details["gui_link_label"] == "Open in Splunk"

        # node summary reflects the click count, not the inherited "(no results or error??)" fallback
        summary = analysis.generate_summary()
        assert summary == "URL Clicks (Splunk): 2 clicks found"
        assert "no results or error" not in summary


@pytest.mark.unit
def test_no_results_summary(test_context):
    splunk = MockMultiSplunk({"app_defender_hunting": []})
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, URL_CONFIG)
        observable = RootAnalysis().add_observable_by_spec(F_URL, "https://evil.example/landing")
        analysis = _run(analyzer, observable)

        assert analysis.details["clicker_events"] == []
        assert analysis.generate_summary() == "URL Clicks (Splunk): no clicks found"


@pytest.mark.unit
def test_multiple_searches_merge_results(test_context):
    splunk = MockMultiSplunk({
        "app_defender_hunting": [ROW_ALLOWED],
        "index=proxy": [PROXY_ROW],
    })
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, MULTI_CONFIG)
        observable = RootAnalysis().add_observable_by_spec(F_URL, "https://evil.example/landing")
        analysis = _run(analyzer, observable)

        events = analysis.get_clicker_events()
        by_source = {e.source for e in events}
        assert by_source == {"splunk:safelinks", "splunk:proxy"}
        assert len(events) == 2

        # safelinks (ClickAllowed) and proxy (escalate_on_any) both escalate
        assert analysis.has_detection_points()
        assert observable.has_directive(DIRECTIVE_CRAWL)


@pytest.mark.unit
def test_escalate_on_any_for_source_without_action_type(test_context):
    # proxy-only config; the single proxy row has no allowed/blocked signal
    config = {"splunk": {"enabled": True, "searches": {"proxy": copy.deepcopy(PROXY)}}}
    splunk = MockMultiSplunk({"index=proxy": [PROXY_ROW]})
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, config)
        observable = RootAnalysis().add_observable_by_spec(F_URL, "https://evil.example/landing")
        analysis = _run(analyzer, observable)

        assert len(analysis.details["clicker_events"]) == 1
        assert analysis.has_detection_points()  # escalate_on_any
        assert observable.has_directive(DIRECTIVE_CRAWL)


@pytest.mark.unit
def test_blocked_only_does_not_escalate(test_context):
    splunk = MockMultiSplunk({"app_defender_hunting": [ROW_BLOCKED]})
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, URL_CONFIG)
        observable = RootAnalysis().add_observable_by_spec(F_URL, "https://evil.example/landing")
        analysis = _run(analyzer, observable)

        assert len(analysis.details["clicker_events"]) == 1
        assert not analysis.has_detection_points()
        assert not observable.has_directive(DIRECTIVE_CRAWL)


@pytest.mark.unit
def test_url_value_expands_to_child_permutations(test_context):
    splunk = MockMultiSplunk({"app_defender_hunting": []})
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, URL_CONFIG)
        observable = RootAnalysis().add_observable_by_spec(
            F_URL, "https://evil.example/login?d=dXNlckBleGFtcGxlLmNvbQ==")
        analysis = _run(analyzer, observable)

        # the last-prepared query carries the OR-group over both permutations
        q = analyzer.target_query
        assert "<O_VALUE>" not in q
        assert '"https://evil.example/login?d=dXNlckBleGFtcGxlLmNvbQ=="' in q
        assert '"https://evil.example/login?d=user@example.com"' in q
        assert " OR " in q
        assert analysis.details["matched_url_count"] == 2


@pytest.mark.unit
def test_fqdn_hit_extracts_clicked_url_without_crawl(test_context):
    splunk = MockMultiSplunk({"app_defender_hunting": [ROW_ALLOWED]})
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, URL_CONFIG)
        observable = RootAnalysis().add_observable_by_spec(F_FQDN, "evil.example")
        analysis = _run(analyzer, observable)

        # the clicked URL is still surfaced as an observable for visibility/pivoting...
        urls = [o for o in analysis.observables if o.type == F_URL]
        assert len(urls) == 1
        assert urls[0].value == "https://evil.example/landing"
        # ...but it is NOT crawled (no flood of Phishkit scans on a busy domain), nor is the fqdn
        assert not urls[0].has_directive(DIRECTIVE_CRAWL)
        assert not observable.has_directive(DIRECTIVE_CRAWL)
        # the clicker is still escalated
        assert analysis.has_detection_points()


@pytest.mark.unit
def test_skipped_phishkit_is_reset_on_hit(test_context):
    from saq.modules.phishkit import PhishkitAnalysis

    splunk = MockMultiSplunk({"app_defender_hunting": [ROW_ALLOWED]})
    with patch("saq.modules.splunk.SplunkClient", return_value=splunk):
        analyzer = _make_analyzer(test_context, URL_CONFIG)
        observable = RootAnalysis().add_observable_by_spec(F_URL, "https://evil.example/landing")
        phishkit_key = MODULE_PATH(PhishkitAnalysis)
        observable._analysis[phishkit_key] = False  # simulate Phishkit having been skipped

        _run(analyzer, observable)

        assert phishkit_key not in observable._analysis  # sentinel cleared
        assert observable.has_directive(DIRECTIVE_CRAWL)
