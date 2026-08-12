import datetime
import sys
from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.engine import CorrelationEngine, CorrelationResult
from saq.collectors.hunter.correlation.registry import (
    QuerySource,
    clear_query_sources,
    register_query_source,
)
from saq.collectors.hunter.correlation.schema import CorrelateConfig, PredefinedCommandConfig, StepConfig


PYTHON = sys.executable


def _make_config(logic_data, timeout="15m"):
    """Helper to create a CorrelateConfig from raw logic data."""
    return CorrelateConfig.model_validate({
        "timeout": timeout,
        "logic": logic_data,
    })


@pytest.fixture(autouse=True)
def _mock_secrets_and_config():
    mock_raw = MagicMock()
    mock_raw._data = {}
    with patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords", return_value={}), \
         patch("saq.collectors.hunter.correlation.engine.get_config", return_value=MagicMock(raw=mock_raw)):
        yield


@pytest.mark.unit
class TestCorrelationEngine:

    def test_no_logic_all_alert(self):
        """Events with no logic steps should all become alerts."""
        config = _make_config([])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"id": 1}, {"id": 2}, {"id": 3}]
        result = engine.execute(events)
        assert len(result.events) == 3
        assert not result.discarded

    def test_filter_action(self):
        """Filter action should remove the event."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"user": "admin"}, {"user": "guest"}, {"user": "admin"}]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.events[0]["user"] == "guest"

    def test_stop_action(self):
        """Stop action should halt processing but keep accumulated alerts."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "stop_here", "property": "action"},
                "execute": [{"action": "stop"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"action": "continue", "id": 1},
            {"action": "stop_here", "id": 2},
            {"action": "continue", "id": 3},
        ]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.events[0]["id"] == 1

    def test_discard_action(self):
        """Discard action should stop everything and set discarded flag."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "discard_all", "property": "action"},
                "execute": [{"action": "discard"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"action": "continue", "id": 1},
            {"action": "discard_all", "id": 2},
            {"action": "continue", "id": 3},
        ]
        result = engine.execute(events)
        assert result.discarded is True

    def test_alert_action_with_overrides(self):
        """Alert action should include queue/analysis_mode overrides."""
        config = _make_config([
            {"action": {"type": "alert", "queue": "high_priority", "analysis_mode": "deep"}},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"id": 1}]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.event_actions[0].queue_override == "high_priority"

    def test_condition_else_branch(self):
        """Else branch should execute when condition is false."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "admin", "property": "user"},
                "execute": [{"action": "alert"}],
                "else": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"user": "admin"}, {"user": "guest"}]
        result = engine.execute(events)
        assert len(result.events) == 1
        assert result.events[0]["user"] == "admin"

    def test_default_alert(self):
        """Events that fall through without an explicit action should become alerts."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "special", "property": "type"},
                "execute": [{"action": {"type": "log", "log_message": "found special"}}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"type": "normal"}]
        result = engine.execute(events)
        assert len(result.events) == 1

    def test_timeout_remaining_events_alert(self):
        """When timeout occurs, remaining events should fall through to alert."""
        config = _make_config([], timeout="1s")
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        # Set timeout to already expired
        engine.timeout = datetime.timedelta(seconds=0)
        events = [{"id": 1}, {"id": 2}]
        result = engine.execute(events)
        assert len(result.events) == 2

    def test_execute_populates_event_duration(self):
        """Every event trace records how long the event took to process."""
        config = _make_config([{"action": {"type": "log", "log_message": "x"}}])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"id": 1}, {"id": 2}])
        assert all(et.duration_ms is not None and et.duration_ms >= 0
                   for et in result.trace.event_traces)
        assert all(step.duration_ms is not None
                   for et in result.trace.event_traces for step in et.steps)

    def test_log_action_continues_processing(self):
        """Log action should not interrupt processing."""
        config = _make_config([
            {"action": {"type": "log", "log_message": "logging {{ _event.id }}", "log_level": "INFO"}},
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [{"id": 1}, {"id": 2}]
        result = engine.execute(events)
        assert len(result.events) == 2

    def test_multiple_conditions_sequential(self):
        """Multiple conditions should be processed in order."""
        config = _make_config([
            {
                "when": {"type": "equals", "value": "noise", "property": "category"},
                "execute": [{"action": "filter"}],
            },
            {
                "when": {"type": "equals", "value": "critical", "property": "severity"},
                "execute": [{"action": {"type": "alert", "queue": "critical"}}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"category": "noise", "severity": "low"},
            {"category": "alert", "severity": "critical"},
            {"category": "alert", "severity": "low"},
        ]
        result = engine.execute(events)
        assert len(result.events) == 2
        # The critical event should have queue override
        assert result.event_actions[1].queue_override == "critical"

    def test_empty_events(self):
        """Empty event list should return empty result."""
        config = _make_config([{"action": "alert"}])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([])
        assert len(result.events) == 0
        assert not result.discarded

    def test_alert_event_origin_indices_tracks_pre_correlation_index(self):
        """`alert_event_origin_indices[i]` should be the engine event_index that produced
        `events[i]` — letting downstream callers map a kept event back to its EventTrace.
        """
        # Filter middle event, keep first and third
        config = _make_config([
            {
                "when": {"type": "equals", "value": "drop", "property": "tag"},
                "execute": [{"action": "filter"}],
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        events = [
            {"id": 1, "tag": "keep"},
            {"id": 2, "tag": "drop"},
            {"id": 3, "tag": "keep"},
        ]
        result = engine.execute(events)
        assert [e["id"] for e in result.events] == [1, 3]
        # Index 1 was filtered; the kept events came from original positions 0 and 2.
        assert result.alert_event_origin_indices == [0, 2]
        # Each kept origin index must correspond to an EventTrace with outcome=alert.
        traces_by_index = {et.event_index: et for et in result.trace.event_traces}
        for origin in result.alert_event_origin_indices:
            assert traces_by_index[origin].outcome == "alert"


class _RecordingSource(QuerySource):
    default_time_field = "_time"
    default_time_format = "iso8601"

    def __init__(self, results=None):
        self.results = results or []
        self.calls = []

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        self.calls.append({
            "query": query,
            "start_time": start_time,
            "end_time": end_time,
            "source_options": source_options,
        })
        return list(self.results)


class _EpochSource(QuerySource):
    default_time_field = "ts"
    default_time_format = "epoch"

    def __init__(self, results=None):
        self.results = results or []
        self.calls = []

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        self.calls.append({
            "query": query,
            "start_time": start_time,
            "end_time": end_time,
            "source_options": source_options,
        })
        return list(self.results)


@pytest.fixture
def _clean_registry():
    clear_query_sources()
    try:
        yield
    finally:
        clear_query_sources()


@pytest.mark.unit
class TestSourceAwareTimeDefaults:
    """Verify that the engine threads hunt_source_type into query commands so
    relative_time_field/format can be omitted on YAML when the source declares defaults."""

    def test_hunt_source_type_supplies_default_field_for_event_query(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        # event-transform query with time_range that omits relative_time_field/format;
        # engine must default to splunk's `_time` / iso8601 because hunt_source_type is "splunk".
        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search index=main",
                        "time_range": {"before": "1h", "after": "1h"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        events = [{"_time": "2024-06-01T00:00:00+00:00"}]
        engine.execute(events)

        assert len(splunk.calls) == 1
        ref = datetime.datetime(2024, 6, 1, 0, 0, tzinfo=datetime.timezone.utc)
        assert splunk.calls[0]["start_time"] == ref - datetime.timedelta(hours=1)
        assert splunk.calls[0]["end_time"] == ref + datetime.timedelta(hours=1)

    def test_missing_default_field_routes_event_to_alert_with_error(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search index=main",
                        "time_range": {"before": "1h", "after": "1h"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        # event lacks the default `_time` field
        events = [{"host": "web1"}]
        result = engine.execute(events)

        assert len(splunk.calls) == 0  # query never reached because resolution failed
        assert len(result.trace.event_traces) == 1
        assert result.trace.event_traces[0].outcome == "error"
        # event still produces an alert per the fail-safe error policy
        assert len(result.events) == 1
        # the error path still stamps durations: the event total and the failing step
        assert result.trace.event_traces[0].duration_ms is not None
        assert result.trace.event_traces[0].steps[0].duration_ms is not None

    def test_stream_mutate_query_switches_current_source(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[{"_time": "2099-01-01T00:00:00+00:00"}])
        epoch = _EpochSource(results=[{"ts": "1717200000"}])  # 2024-06-01 00:00:00 UTC
        register_query_source("splunk", splunk)
        register_query_source("epoch_src", epoch)

        # step 1: stream-mutate query against epoch_src replaces the stream and
        # switches current source to epoch_src.
        # step 2: event-transform query against splunk; because current source is now
        # epoch_src, default field is `ts` (epoch). The new event's `ts` should anchor
        # the time range; if defaults still pointed to splunk's `_time` we'd fail
        # because the new event has no `_time`.
        config = _make_config([
            {
                "transform": {
                    "type": "stream",
                    "method": "mutate",
                    "command": {
                        "type": "query",
                        "source": "epoch_src",
                        "query": "epoch search",
                        "time_range": {"before": "1h"},
                    },
                },
            },
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "context",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search lookup",
                        "time_range": {"before": "30m", "after": "30m"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        # initial event has _time so the stream-mutate query (anchored to the hunt window) runs fine
        engine.execute([{"_time": "2024-05-31T00:00:00+00:00"}])

        # second query (after the stream mutate) should be anchored to ts=1717200000
        assert len(splunk.calls) == 1
        ref = datetime.datetime.fromtimestamp(1717200000, tz=datetime.timezone.utc)
        assert splunk.calls[0]["start_time"] == ref - datetime.timedelta(minutes=30)
        assert splunk.calls[0]["end_time"] == ref + datetime.timedelta(minutes=30)

    def test_stream_transform_query_anchored_to_hunt_window(self, _clean_registry, tmpdir):
        """A stream transform's relative time_range is anchored to the hunt's query
        window — `before` extends before hunt_start_time, `after` after hunt_end_time —
        not to the wall-clock execution time or any single event timestamp."""
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        config = _make_config([
            {
                "transform": {
                    "type": "stream",
                    "method": "mutate",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search index=main",
                        "time_range": {"before": "3h", "after": "1h"},
                    },
                },
            },
        ])
        hunt_start = datetime.datetime(2026, 5, 4, 0, 0, tzinfo=datetime.timezone.utc)
        hunt_end = datetime.datetime(2026, 5, 5, 0, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_start, hunt_end, hunt_source_type="splunk")
        # the event carries a _time far outside the hunt window; it must be ignored
        engine.execute([{"_time": "2099-01-01T00:00:00+00:00"}])

        assert len(splunk.calls) == 1
        assert splunk.calls[0]["start_time"] == hunt_start - datetime.timedelta(hours=3)
        assert splunk.calls[0]["end_time"] == hunt_end + datetime.timedelta(hours=1)

    def test_stream_merge_preserves_triggering_trace(self, _clean_registry, tmpdir):
        """A stream transform resets the stream, but the trace of the event that
        triggered it must survive — it holds the only record of the transform's
        rendered command, result count, and merge-dropped count.
        Regression: the _StreamReset handler used to wipe trace.event_traces
        entirely, leaving the stream transform invisible in the UI."""
        splunk = _RecordingSource(results=[
            {"ts": "1717200000", "data": "new1"},  # parseable epoch timestamp
            {"data": "no_timestamp"},              # dropped by merge — missing ts
        ])
        register_query_source("splunk", splunk)

        config = _make_config([
            {
                "transform": {
                    "type": "stream",
                    "method": "merge",
                    "merge_time_spec": {
                        "l_field": "ts", "l_format": "epoch",
                        "r_field": "ts", "r_format": "epoch",
                    },
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search host={{ _event.host }}",
                        "time_range": {"before": "1h"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        events = [{"ts": "1717100000", "host": "web1", "id": 1}]
        result = engine.execute(events)

        # the merge produced a new 2-event stream (1 existing + 1 new with a timestamp)
        assert len(result.events) == 2

        # a stream_reset stream-event was recorded
        assert any(se.event_type == "stream_reset" for se in result.trace.stream_events)

        # the triggering event trace survived the reset and is first
        triggering = result.trace.event_traces[0]
        assert triggering.outcome == "stream_reset"
        assert len(triggering.steps) == 1
        transform_step = triggering.steps[0].step
        assert transform_step.trace_type == "transform"
        assert transform_step.transform_type == "stream"
        assert transform_step.method == "merge"
        # the rendered query is preserved (per-event template was rendered)
        assert transform_step.rendered_command == "search host=web1"
        # result_count reflects the rows the command returned
        assert transform_step.result_count == 2
        # merge_dropped surfaces the row dropped for a missing timestamp
        assert transform_step.merge_dropped == 1

    def test_resolve_command_source_handles_defined_query(self, _clean_registry):
        splunk = _RecordingSource()
        register_query_source("splunk", splunk)

        from saq.collectors.hunter.correlation.schema import CommandConfig

        predef = PredefinedCommandConfig(
            name="splunk_lookup", type="query", source="splunk", query="search foo",
        )
        engine = CorrelationEngine(
            _make_config([]), [predef], datetime.datetime.now(datetime.timezone.utc),
            hunt_source_type="splunk",
        )
        defined_cmd = CommandConfig(type="defined", name="splunk_lookup")
        assert engine._resolve_command_source(defined_cmd) == "splunk"
        # executable defined commands return None (don't switch source on stream mutate)
        exec_predef = PredefinedCommandConfig(name="ext", type="executable", path="/bin/true")
        engine.predefined_commands = [exec_predef]
        defined_exec = CommandConfig(type="defined", name="ext")
        assert engine._resolve_command_source(defined_exec) is None


@pytest.mark.unit
class TestTransformTraceQueryTimespec:
    """The Correlation Trace UI needs to display the time window each query ran
    against, so analysts can rerun the same query in the underlying data source.
    These tests verify the engine captures resolved bounds and a source-native
    display string on each TransformTrace."""

    def test_event_query_captures_event_anchored_time_range(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search index=main",
                        "time_range": {"before": "30d", "after": "0s"},
                    },
                },
            },
        ])
        hunt_time = datetime.datetime(2026, 5, 18, 12, 31, 32, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_time, hunt_source_type="splunk")
        event_time = datetime.datetime(2026, 5, 18, 12, 31, 32, tzinfo=datetime.timezone.utc)
        result = engine.execute([{"_time": event_time.isoformat()}])

        et = result.trace.event_traces[0]
        transform = et.steps[0].step
        assert transform.query_start_time == event_time - datetime.timedelta(days=30)
        assert transform.query_end_time == event_time
        # _RecordingSource doesn't override format_timespec_for_display, so the
        # ABC default applies (None) — the UI will fall back to a separate
        # decorative block built from the raw query_start_time/query_end_time.
        assert transform.query_time_spec is None

    def test_stream_query_captures_hunt_window_anchored_time_range(self, _clean_registry, tmpdir):
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        config = _make_config([
            {
                "transform": {
                    "type": "stream",
                    "method": "mutate",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search index=main",
                        "time_range": {"before": "3h", "after": "1h"},
                    },
                },
            },
        ])
        hunt_start = datetime.datetime(2026, 5, 4, 0, 0, tzinfo=datetime.timezone.utc)
        hunt_end = datetime.datetime(2026, 5, 5, 0, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [], hunt_start, hunt_end, hunt_source_type="splunk")
        result = engine.execute([{"_time": "2099-01-01T00:00:00+00:00"}])

        # the trace surviving a stream_reset belongs to the triggering event
        transform = result.trace.event_traces[0].steps[0].step
        assert transform.query_start_time == hunt_start - datetime.timedelta(hours=3)
        assert transform.query_end_time == hunt_end + datetime.timedelta(hours=1)
        # _RecordingSource uses the ABC default → None (no inline-prefix syntax).
        assert transform.query_time_spec is None

    def test_executable_transform_has_no_query_timespec(self, _clean_registry, tmpdir):
        """Executables don't run against a QuerySource — the timespec fields stay None."""
        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "enriched",
                    "property_type": "str",
                    "command": {"type": "executable", "path": "/bin/echo", "args": ["x"]},
                },
            },
        ])
        engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
        result = engine.execute([{"id": 1}])

        transform = result.trace.event_traces[0].steps[0].step
        assert transform.query_start_time is None
        assert transform.query_end_time is None
        assert transform.query_time_spec is None

    def test_defined_query_command_captures_time_range(self, _clean_registry, tmpdir):
        """A `defined` command that resolves to a query gets the same trace fields
        as a direct query — the engine follows the predef indirection."""
        splunk = _RecordingSource(results=[])
        register_query_source("splunk", splunk)

        predef = PredefinedCommandConfig(
            name="splunk_lookup", type="query", source="splunk",
            query="search index=main", time_range={"before": "1h"},
        )
        config = _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "command": {"type": "defined", "name": "splunk_lookup"},
                },
            },
        ])
        hunt_time = datetime.datetime(2026, 5, 18, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(config, [predef], hunt_time, hunt_source_type="splunk")
        event_time = datetime.datetime(2026, 5, 18, 11, 30, tzinfo=datetime.timezone.utc)
        result = engine.execute([{"_time": event_time.isoformat()}])

        transform = result.trace.event_traces[0].steps[0].step
        assert transform.query_start_time == event_time - datetime.timedelta(hours=1)
        assert transform.query_end_time == event_time


@pytest.mark.unit
class TestCorrelateReplay:
    """Capture-and-replay of follow-up correlate query results (validate.py
    --save-correlate-results / --correlate-results-file)."""

    def _config(self):
        # per-event query: each event renders a distinct query, so capture/replay
        # must key on the rendered text (the existing template-keyed cache cannot).
        return _make_config([
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": "lookup",
                    "property_type": "list",
                    "command": {
                        "type": "query",
                        "source": "splunk",
                        "query": "search host={{ _event.host }}",
                        "time_range": {"before": "1h", "after": "1h"},
                    },
                },
            },
        ])

    def test_live_run_captures_rendered_queries(self, _clean_registry):
        splunk = _RecordingSource(results=[{"found": True}])
        register_query_source("splunk", splunk)
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(self._config(), [], hunt_time, hunt_source_type="splunk")
        events = [
            {"host": "web1", "_time": "2024-06-01T11:00:00+00:00"},
            {"host": "web2", "_time": "2024-06-01T11:00:00+00:00"},
        ]
        result = engine.execute(events)

        # each event got its property and the live source was hit once per event
        assert all(e["lookup"] == [{"found": True}] for e in result.events)
        assert len(splunk.calls) == 2
        captured = {r["query"]: r["results"] for r in result.captured_queries}
        assert captured == {
            "search host=web1": [{"found": True}],
            "search host=web2": [{"found": True}],
        }

    def test_replay_skips_live_source(self, _clean_registry):
        # a source that fails if ever called — proves replay is fully offline
        splunk = _RecordingSource(results=[{"should": "not be used"}])
        register_query_source("splunk", splunk)
        replay = [
            {"source": "splunk", "query": "search host=web1", "results": [{"saved": "web1"}]},
            {"source": "splunk", "query": "search host=web2", "results": [{"saved": "web2"}]},
        ]
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        engine = CorrelationEngine(
            self._config(), [], hunt_time, hunt_source_type="splunk", correlate_replay=replay,
        )
        events = [
            {"host": "web1", "_time": "2024-06-01T11:00:00+00:00"},
            {"host": "web2", "_time": "2024-06-01T11:00:00+00:00"},
        ]
        result = engine.execute(events)

        assert len(splunk.calls) == 0  # no live queries on a full replay
        by_host = {e["host"]: e["lookup"] for e in result.events}
        assert by_host == {"web1": [{"saved": "web1"}], "web2": [{"saved": "web2"}]}

    def test_capture_roundtrips_through_replay(self, _clean_registry):
        splunk = _RecordingSource(results=[{"found": True}])
        register_query_source("splunk", splunk)
        hunt_time = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        events = [{"host": "web1", "_time": "2024-06-01T11:00:00+00:00"}]

        # capture from a live run, then replay that capture verbatim
        live = CorrelationEngine(self._config(), [], hunt_time, hunt_source_type="splunk")
        captured = live.execute(events).captured_queries

        splunk.calls.clear()
        replayed = CorrelationEngine(
            self._config(), [], hunt_time, hunt_source_type="splunk", correlate_replay=captured,
        ).execute(events)
        assert len(splunk.calls) == 0
        assert replayed.events[0]["lookup"] == [{"found": True}]


class _ClockAdvancingSource(QuerySource):
    """A query source that consumes wall-clock time when queried, simulating a slow
    backend. Used to drive the per-step correlate timeout deterministically: the
    transform's query advances the (mocked) clock past the timeout so the *next*
    per-step check trips."""
    default_time_field = "_time"
    default_time_format = "iso8601"

    def __init__(self, clock, advance, results=None):
        self.clock = clock
        self.advance = advance
        self.results = results or []
        self.calls = []

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        self.calls.append(query)
        self.clock["t"] = self.clock["t"] + self.advance
        return list(self.results)


@pytest.mark.unit
class TestTransformThenFilterAndTimeout:
    """Regression coverage for the azure_sspr_spray production incident: a transform
    followed by a filtering `when` inside a condition's execute list, and the correlate
    timeout being surfaced visibly when it truncates an event partway through its steps.

    Structure mirrors the hunt: condition(success) -> [log, transform(query->count),
    when(count>0 -> filter)]."""

    def _sspr_like_config(self, timeout="15m"):
        return _make_config([
            {
                "when": {"type": "equals", "value": "yes", "property": "is_success"},
                "execute": [
                    {"action": {"type": "log", "log_message": "{{ _event.ip }} success"}},
                    {
                        "description": "Step: Filter if Azure Trusted Named Location",
                        "transform": {
                            "type": "event",
                            "method": "property",
                            "property_name": "correlate_trusted_location",
                            "property_type": "list",
                            "command": {
                                "type": "query",
                                "source": "splunk",
                                "query": "search trusted ip={{ _event.ip }}",
                                "time_range": {"before": "3d"},
                            },
                        },
                    },
                    {
                        "when": {
                            "type": "jinja",
                            "value": "{{ (_event.correlate_trusted_location[0].count | int) > 0 }}",
                        },
                        "execute": [{"action": {"type": "filter", "log_message": "trusted"}}],
                        "else": [{"action": {"type": "log", "log_message": "not trusted"}}],
                    },
                ],
            },
        ], timeout=timeout)

    def test_filtering_condition_after_transform_runs(self, _clean_registry):
        """The `when` filter following an event transform must execute: an event whose
        trusted-location query returns count>0 is filtered, not alerted. (This is the
        behavior the production trace appeared to violate — it was actually a timeout.)"""
        splunk = _RecordingSource(results=[{"count": "1"}])
        register_query_source("splunk", splunk)
        engine = CorrelationEngine(
            self._sspr_like_config(), [],
            datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc),
            hunt_source_type="splunk",
        )
        events = [{"_time": "2024-06-01T00:00:00+00:00", "ip": "1.2.3.4", "is_success": "yes"}]
        result = engine.execute(events)

        # filtered out -> no alert
        assert result.events == []
        et = result.trace.event_traces[0]
        assert et.outcome == "filter"
        # the outer condition's branch_steps must include the log, the transform, AND
        # the trailing `when` (i.e. execution did not stop after the transform)
        branch = et.steps[0].step.branch_steps
        assert [s.step.trace_type for s in branch] == ["action", "transform", "condition"]
        assert branch[2].step.branch_taken == "execute"  # count>0 -> filter branch

    def test_midevent_timeout_is_visible_and_fails_safe(self, _clean_registry):
        """A correlate timeout reached partway through an event must be surfaced, not
        silent: outcome=timeout, a timeout stream_event is recorded, the partial trace
        (log + transform, no `when`) is preserved, and the event still alerts."""
        clock = {"t": datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)}
        # transform query consumes 20m; correlate timeout is 15m -> the next per-step
        # check (the `when`) trips.
        slow = _ClockAdvancingSource(clock, datetime.timedelta(minutes=20), results=[{"count": "1"}])
        register_query_source("splunk", slow)
        engine = CorrelationEngine(
            self._sspr_like_config(timeout="15m"), [], clock["t"],
            hunt_source_type="splunk", hunt_name="SSPR spray", hunt_uuid="abc-123",
        )
        events = [{"_time": "2024-06-01T00:00:00+00:00", "ip": "1.2.3.4", "is_success": "yes"}]

        with patch("saq.collectors.hunter.correlation.engine.datetime") as mdt:
            mdt.datetime.now.side_effect = lambda tz=None: clock["t"]
            mdt.timezone = datetime.timezone
            mdt.timedelta = datetime.timedelta
            result = engine.execute(events)

        # fail-safe: the event still becomes an alert (never silently dropped)
        assert len(result.events) == 1
        assert result.event_actions[0].action_type == "alert"
        # but the outcome is explicitly a timeout, not a clean alert
        et = result.trace.event_traces[0]
        assert et.outcome == "timeout"
        # a stream-level timeout event is recorded for visibility
        assert any(se.event_type == "timeout" and se.at_event_index == 0
                   for se in result.trace.stream_events)
        # partial trace preserved: the log + transform ran, the `when` did not
        branch = et.steps[0].step.branch_steps
        assert [s.step.trace_type for s in branch] == ["action", "transform"]
        # the transform's query did run once before the budget was exhausted
        assert len(slow.calls) == 1


@pytest.mark.unit
class TestSecretLoadFailure:
    """A degraded secret store must fail the step, not export an empty credential."""

    def test_secret_export_failure_fails_env_step_loudly(self):
        mock_raw = MagicMock()
        mock_raw._data = {}
        with patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords",
                   side_effect=RuntimeError("no encryption key")), \
             patch("saq.collectors.hunter.correlation.engine.get_config",
                   return_value=MagicMock(raw=mock_raw)):
            config = _make_config([
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "result",
                        "command": {
                            "type": "executable",
                            "path": PYTHON,
                            "args": ["-c", "import os; print(os.environ['API_KEY'])"],
                            "env": {"API_KEY": "{{ _secrets['vendor.api_key'] }}"},
                        },
                    },
                },
            ])
            engine = CorrelationEngine(config, [], datetime.datetime.now(datetime.timezone.utc))
            result = engine.execute([{"id": 1}])

        et = result.trace.event_traces[0]
        assert et.outcome == "error"
        assert "no secrets are loaded" in et.steps[0].step.error
