from datetime import datetime, timezone

import pytest

from saq.clicker_detection.timeline import (
    ClickerEvent,
    REGISTERED_CLICKER_PROVIDERS,
    gather_clicker_events,
    gather_clicker_results,
    register_clicker_event_provider,
)


@pytest.mark.unit
def test_clicker_event_normalizes_naive_timestamp():
    e = ClickerEvent(source="splunk", timestamp=datetime(2026, 6, 17, 12, 0, 0))
    assert e.timestamp.tzinfo == timezone.utc


@pytest.mark.unit
def test_register_clicker_event_provider_idempotent():
    class _P:
        pass
    n = len(REGISTERED_CLICKER_PROVIDERS)
    register_clicker_event_provider(_P)
    register_clicker_event_provider(_P)
    try:
        assert REGISTERED_CLICKER_PROVIDERS.count(_P) == 1
        assert len(REGISTERED_CLICKER_PROVIDERS) == n + 1
    finally:
        REGISTERED_CLICKER_PROVIDERS.remove(_P)


class _FakeRoot:
    """Minimal stand-in for RootAnalysis.get_analysis_by_type used by gather_clicker_events."""
    def __init__(self, by_type):
        self._by_type = by_type

    def get_analysis_by_type(self, cls):
        return self._by_type.get(cls, [])


@pytest.mark.unit
def test_gather_clicker_events_sorts_and_filters(monkeypatch):
    class GoodAnalysis:
        def get_clicker_events(self):
            return [
                ClickerEvent(source="splunk", timestamp=datetime(2026, 6, 17, 12, 5, tzinfo=timezone.utc), user="b"),
                ClickerEvent(source="splunk", timestamp=datetime(2026, 6, 17, 12, 1, tzinfo=timezone.utc), user="a"),
                ClickerEvent(source="splunk", timestamp=None, user="no_time"),
                "not-an-event",  # ignored
            ]

    monkeypatch.setattr(
        "saq.clicker_detection.timeline.REGISTERED_CLICKER_PROVIDERS", [GoodAnalysis]
    )
    root = _FakeRoot({GoodAnalysis: [GoodAnalysis()]})
    events = gather_clicker_events(root)

    assert [e.user for e in events] == ["a", "b", "no_time"]  # sorted asc, None last


@pytest.mark.unit
def test_gather_clicker_events_tolerates_provider_exception(monkeypatch):
    class BoomAnalysis:
        def get_clicker_events(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "saq.clicker_detection.timeline.REGISTERED_CLICKER_PROVIDERS", [BoomAnalysis]
    )
    root = _FakeRoot({BoomAnalysis: [BoomAnalysis()]})
    # must not raise; just yields nothing
    assert gather_clicker_events(root) == []


@pytest.mark.unit
def test_gather_clicker_results_ran_with_no_events(monkeypatch):
    """A provider analysis that ran but produced no events -> ran is True, events empty."""
    class EmptyAnalysis:
        def get_clicker_events(self):
            return []

    monkeypatch.setattr(
        "saq.clicker_detection.timeline.REGISTERED_CLICKER_PROVIDERS", [EmptyAnalysis]
    )
    root = _FakeRoot({EmptyAnalysis: [EmptyAnalysis()]})
    results = gather_clicker_results(root)
    assert results.ran is True
    assert results.events == []
    assert results.errors == []


@pytest.mark.unit
def test_gather_clicker_results_collects_errors(monkeypatch):
    """Provider exposing get_clicker_error -> error surfaced; still counts as ran."""
    class ErrorAnalysis:
        def get_clicker_events(self):
            return []

        def get_clicker_error(self):
            return "splunk: search timed out"

    monkeypatch.setattr(
        "saq.clicker_detection.timeline.REGISTERED_CLICKER_PROVIDERS", [ErrorAnalysis]
    )
    root = _FakeRoot({ErrorAnalysis: [ErrorAnalysis()]})
    results = gather_clicker_results(root)
    assert results.ran is True
    assert results.errors == ["splunk: search timed out"]


@pytest.mark.unit
def test_gather_clicker_results_not_ran_when_no_provider_analysis(monkeypatch):
    """No provider analysis in the tree -> ran is False (card stays hidden)."""
    class NeverRanAnalysis:
        def get_clicker_events(self):
            return []

    monkeypatch.setattr(
        "saq.clicker_detection.timeline.REGISTERED_CLICKER_PROVIDERS", [NeverRanAnalysis]
    )
    root = _FakeRoot({})  # provider registered, but no instance in the tree
    results = gather_clicker_results(root)
    assert results.ran is False
    assert results.events == []
    assert results.errors == []


