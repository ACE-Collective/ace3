import datetime
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.engine import CorrelationEngine
from saq.collectors.hunter.correlation.registry import (
    QuerySource,
    clear_query_sources,
    register_query_source,
)
from saq.collectors.hunter.correlation.schema import (
    CorrelateConfig,
    PredefinedCommandConfig,
)

PYTHON = sys.executable


class MockQuerySource(QuerySource):
    def __init__(self, results=None):
        self.results = results or []

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        return self.results


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_query_sources()
    yield
    clear_query_sources()


@pytest.fixture(autouse=True)
def _mock_secrets_and_config():
    mock_raw = MagicMock()
    mock_raw._data = {}
    with patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords", return_value={}), \
         patch("saq.collectors.hunter.correlation.engine.get_config", return_value=MagicMock(raw=mock_raw)):
        yield


@pytest.mark.unit
class TestCorrelationIntegration:

    def test_full_pipeline_filter_and_alert(self):
        """End-to-end: filter noise, alert on real events."""
        config_data = {
            "timeout": "5m",
            "logic": [
                {
                    "when": {"type": "glob", "value": "*.internal.corp", "property": "hostname"},
                    "execute": [{"action": "filter"}],
                },
                {
                    "when": {"type": "regex", "value": r"admin|root", "property": "username"},
                    "execute": [
                        {"action": {"type": "alert", "queue": "high_priority"}},
                    ],
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [
            {"hostname": "web1.internal.corp", "username": "admin"},  # filtered (internal)
            {"hostname": "external.evil.com", "username": "admin"},    # alert (admin on external)
            {"hostname": "external.evil.com", "username": "guest"},    # alert (default)
            {"hostname": "db.internal.corp", "username": "root"},      # filtered (internal)
        ]

        result = engine.execute(events)
        assert len(result.events) == 2
        assert result.events[0]["username"] == "admin"
        assert result.events[1]["username"] == "guest"
        assert result.event_actions[1].queue_override == "high_priority"

    def test_predefined_command_with_executable(self, tmpdir):
        """Test using a predefined executable command for enrichment."""
        predef = PredefinedCommandConfig(
            name="enrich_user",
            type="executable",
            path=PYTHON,
            args=["-c", "print('default')"],
        )

        config_data = {
            "logic": [
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "enrichment",
                        "command": {
                            "type": "defined",
                            "name": "enrich_user",
                            "arguments": {
                                "args": ["-c", "import sys; print(f'enriched_{sys.argv[1]}')", "{{ _event.user }}"],
                            },
                        },
                    },
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [predef], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [{"user": "admin"}, {"user": "guest"}]
        result = engine.execute(events)
        assert len(result.events) == 2
        assert result.events[0]["enrichment"] == "enriched_admin"
        assert result.events[1]["enrichment"] == "enriched_guest"

    def test_condition_with_nested_logic(self):
        """Test nested conditions with else branches."""
        config_data = {
            "logic": [
                {
                    "when": {"type": "equals", "value": "high", "property": "severity"},
                    "execute": [
                        {
                            "when": {"type": "equals", "value": "admin", "property": "user"},
                            "execute": [
                                {"action": {"type": "alert", "queue": "critical"}},
                            ],
                            "else": [
                                {"action": {"type": "alert", "queue": "high"}},
                            ],
                        },
                    ],
                    "else": [
                        {"action": "filter"},
                    ],
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [
            {"severity": "high", "user": "admin"},   # critical queue
            {"severity": "high", "user": "guest"},    # high queue
            {"severity": "low", "user": "admin"},     # filtered
        ]

        result = engine.execute(events)
        assert len(result.events) == 2
        assert result.event_actions[0].queue_override == "critical"
        assert result.event_actions[1].queue_override == "high"

    def test_discard_clears_all_alerts(self):
        """Test that discard stops everything and discards alerts."""
        config_data = {
            "logic": [
                {
                    "when": {"type": "equals", "value": "poison", "property": "type"},
                    "execute": [{"action": "discard"}],
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [
            {"type": "normal", "id": 1},
            {"type": "poison", "id": 2},
            {"type": "normal", "id": 3},
        ]

        result = engine.execute(events)
        assert result.discarded is True

    def test_stop_preserves_earlier_alerts(self):
        """Test that stop preserves alerts from events processed before the stop."""
        config_data = {
            "logic": [
                {
                    "when": {"type": "equals", "value": "stop", "property": "cmd"},
                    "execute": [{"action": "stop"}],
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [
            {"cmd": "continue", "id": 1},
            {"cmd": "continue", "id": 2},
            {"cmd": "stop", "id": 3},
            {"cmd": "continue", "id": 4},
        ]

        result = engine.execute(events)
        assert len(result.events) == 2
        assert result.events[0]["id"] == 1
        assert result.events[1]["id"] == 2

    def test_stream_mutate_transform(self, tmpdir):
        """Test stream mutate replaces the event stream."""
        config_data = {
            "logic": [
                {
                    "transform": {
                        "type": "stream",
                        "method": "mutate",
                        "command": {
                            "type": "executable",
                            "path": PYTHON,
                            "args": ["-c", "import json; [print(json.dumps(e)) for e in [{'new': 1}, {'new': 2}]]"],
                        },
                    },
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [{"old": 1}, {"old": 2}, {"old": 3}]
        result = engine.execute(events)
        assert len(result.events) == 2
        assert result.events[0] == {"new": 1}
        assert result.events[1] == {"new": 2}

    def test_stream_merge_transform(self, tmpdir):
        """Stream merge interleaves query results into the stream by timestamp and
        keeps the triggering transform's trace visible through the stream reset."""
        splunk = MockQuerySource(results=[{"ts": "1500", "src": "merged"}])
        register_query_source("splunk", splunk)

        config_data = {
            "logic": [
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
                            "query": "search all",
                            "time_range": {"before": "1h"},
                        },
                    },
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [{"ts": "1000", "src": "original1"}, {"ts": "2000", "src": "original2"}]
        result = engine.execute(events)

        # merged stream interleaved by timestamp: original1 (1000), merged (1500), original2 (2000)
        assert [e["src"] for e in result.events] == ["original1", "merged", "original2"]

        # the stream reset is recorded and the transform that drove it stays in the trace
        assert any(se.event_type == "stream_reset" for se in result.trace.stream_events)
        triggering = result.trace.event_traces[0]
        assert triggering.outcome == "stream_reset"
        transform_step = triggering.steps[0].step
        assert transform_step.trace_type == "transform"
        assert transform_step.method == "merge"
        assert transform_step.result_count == 1
        assert transform_step.merge_dropped == 0

    def test_jinja_expression_with_events_access(self):
        """Test that _events is accessible in jinja expressions."""
        config_data = {
            "logic": [
                {
                    "when": "{{ _events | length > 2 }}",
                    "execute": [
                        {"action": {"type": "log", "log_message": "stream has {{ _events | length }} events"}},
                    ],
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [{"id": 1}, {"id": 2}, {"id": 3}]
        result = engine.execute(events)
        # All events should still become alerts (log doesn't interrupt)
        assert len(result.events) == 3

    @patch("saq.collectors.hunter.correlation.engine.get_config")
    @patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords")
    def test_secrets_not_bound_in_jinja_condition(self, mock_secrets, mock_config):
        """_secrets must not be reachable from a correlation condition.

        `is undefined` is asserted directly rather than asserting the condition is merely
        false, which any evaluation error would also produce.
        """
        mock_secrets.return_value = {"api_key": "secret_value"}
        mock_raw = MagicMock()
        mock_raw._data = {}
        mock_config.return_value = MagicMock(raw=mock_raw)

        config_data = {
            "logic": [
                {
                    "when": "{{ _secrets is undefined }}",
                    "execute": [{"action": "filter"}],
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [{"id": 1}]
        result = engine.execute(events)
        assert len(result.events) == 0  # filtered because _secrets is undefined

    @patch("saq.collectors.hunter.correlation.engine.get_config")
    @patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords")
    def test_config_accessible_in_jinja_condition(self, mock_secrets, mock_config):
        """Test that _config is accessible in jinja expressions during full pipeline."""
        mock_secrets.return_value = {}
        mock_raw = MagicMock()
        mock_raw._data = {"global": {"environment": "production"}}
        mock_config.return_value = MagicMock(raw=mock_raw)

        config_data = {
            "logic": [
                {
                    "when": "{{ _config.global.environment == 'production' }}",
                    "execute": [{"action": "filter"}],
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [{"id": 1}]
        result = engine.execute(events)
        assert len(result.events) == 0  # filtered because config matched

    @patch("saq.collectors.hunter.correlation.engine.get_config")
    @patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords")
    def test_secrets_bound_in_executable_env(self, mock_secrets, mock_config):
        """_secrets renders into an executable command's environment.

        This is the one channel where handing a credential to a local helper process is the
        point of the feature.
        """
        mock_secrets.return_value = {"db_pass": "s3cret"}
        mock_raw = MagicMock()
        mock_raw._data = {}
        mock_config.return_value = MagicMock(raw=mock_raw)

        config_data = {
            "logic": [
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "result",
                        "command": {
                            "type": "executable",
                            "path": PYTHON,
                            "args": ["-c", "import os; print(os.environ['PROBE'])"],
                            "env": {"PROBE": "{{ _secrets['db_pass'] }}"},
                        },
                    },
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        events = [{"id": 1}]
        result = engine.execute(events)
        # the secret binds into env (the redaction only fires because "s3cret" was present in the
        # output), but stdout becomes event data and is sanitized on the way out, so the raw
        # credential never lands in the event stream / persisted trace.
        assert result.events[0]["result"] == "***"

    @patch("saq.collectors.hunter.correlation.engine.get_config")
    @patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords")
    def test_secrets_not_bound_in_executable_args(self, mock_secrets, mock_config):
        """_secrets must not reach `args` -- argv is readable by other users via /proc."""
        mock_secrets.return_value = {"db_pass": "s3cret"}
        mock_raw = MagicMock()
        mock_raw._data = {}
        mock_config.return_value = MagicMock(raw=mock_raw)

        config_data = {
            "logic": [
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "result",
                        "command": {
                            "type": "executable",
                            "path": PYTHON,
                            "args": ["-c", "import sys; print(sys.argv[1])", "{{ _secrets is undefined }}"],
                        },
                    },
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        result = engine.execute([{"id": 1}])
        assert result.events[0]["result"] == "True"

    @patch("saq.collectors.hunter.correlation.engine.get_config")
    @patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords")
    def test_secrets_not_bound_in_query_text(self, mock_secrets, mock_config):
        """_secrets must not reach query text -- it is sent to a third-party data source."""
        mock_secrets.return_value = {"db_pass": "s3cret"}
        mock_raw = MagicMock()
        mock_raw._data = {}
        mock_config.return_value = MagicMock(raw=mock_raw)

        class _RecordingSource(QuerySource):
            def __init__(self):
                self.queries = []

            def execute_query(self, query, start_time, end_time, timeout, source_options=None):
                self.queries.append(query)
                return [{"matched": True}]

        source = _RecordingSource()
        register_query_source("mock", source)

        config_data = {
            "logic": [
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "result",
                        "command": {
                            "type": "query",
                            "source": "mock",
                            "query": "search probe={{ _secrets is undefined }}",
                        },
                    },
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime.now(datetime.timezone.utc),
        )

        engine.execute([{"id": 1}])
        assert source.queries == ["search probe=True"]

    @patch("saq.collectors.hunter.correlation.engine.get_config")
    @patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords")
    def test_unresolved_encrypted_marker_in_env_is_an_error(self, mock_secrets, mock_config):
        """An env value that renders to an `encrypted:` marker must fail the step.

        Reproduces the rapid7 bug: `_config` is the pre-validation merged dict, so an
        `encrypted:<name>` marker survives there unresolved. Rendering it into env hands
        the literal marker to the helper script as its API key, and the only symptom is a
        confusing auth failure against the vendor.
        """
        mock_secrets.return_value = {"rapid7.api_key": "REAL_KEY"}
        mock_raw = MagicMock()
        mock_raw._data = {"rapid7": {"api_key": "encrypted:rapid7.api_key"}}
        mock_config.return_value = MagicMock(raw=mock_raw)

        predefined = [PredefinedCommandConfig.model_validate({
            "name": "get_r7_comments",
            "type": "executable",
            "path": PYTHON,
            "args": ["-c", "import os; print(os.environ['R7_API_KEY'])"],
            "env": {"R7_API_KEY": "{{ _config['rapid7']['api_key'] }}"},
        })]
        config = CorrelateConfig.model_validate({
            "logic": [
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "comments",
                        "command": {"type": "defined", "name": "get_r7_comments"},
                    },
                },
            ],
        })
        engine = CorrelationEngine(
            config, predefined, datetime.datetime.now(datetime.timezone.utc),
        )

        result = engine.execute([{"id": 1}])
        event_trace = result.trace.event_traces[0]
        assert event_trace.outcome == "error"
        assert "R7_API_KEY" in event_trace.steps[0].step.error

    @patch("saq.collectors.hunter.correlation.engine.get_config")
    @patch("saq.collectors.hunter.correlation.engine.export_encrypted_passwords")
    def test_secret_renders_into_env_via_secrets_namespace(self, mock_secrets, mock_config):
        """`_secrets` is the supported way to get a credential into an env value."""
        mock_secrets.return_value = {"rapid7.api_key": "REAL_KEY"}
        mock_raw = MagicMock()
        mock_raw._data = {"rapid7": {"api_key": "encrypted:rapid7.api_key"}}
        mock_config.return_value = MagicMock(raw=mock_raw)

        predefined = [PredefinedCommandConfig.model_validate({
            "name": "get_r7_comments",
            "type": "executable",
            "path": PYTHON,
            "args": ["-c", "import os; print(os.environ['R7_API_KEY'])"],
            "env": {"R7_API_KEY": "{{ _secrets['rapid7.api_key'] }}"},
        })]
        config = CorrelateConfig.model_validate({
            "logic": [
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "comments",
                        "command": {"type": "defined", "name": "get_r7_comments"},
                    },
                },
            ],
        })
        engine = CorrelationEngine(
            config, predefined, datetime.datetime.now(datetime.timezone.utc),
        )

        result = engine.execute([{"id": 1}])
        # env binding works (redaction fired on "REAL_KEY"), but stdout is sanitized before it
        # becomes event data, so the credential does not leak into the stream or the trace.
        assert result.events[0]["comments"] == "***"

    def test_splunk_hunt_omits_relative_time_field_uses_default(self):
        """End-to-end: a splunk hunt's correlate query omits relative_time_field/format
        and the engine fills them in from SplunkQuerySource's class defaults so the
        query window is anchored to the event's `_time`."""

        class _RecordingSplunkSource(QuerySource):
            default_time_field = "_time"
            default_time_format = "iso8601"

            def __init__(self):
                self.calls = []

            def execute_query(self, query, start_time, end_time, timeout, source_options=None):
                self.calls.append({"start_time": start_time, "end_time": end_time})
                return [{"matched": True}]

        splunk = _RecordingSplunkSource()
        register_query_source("splunk", splunk)

        # YAML-equivalent dict: time_range has only before/after; no relative_time_field/format
        config_data = {
            "timeout": "5m",
            "logic": [
                {
                    "transform": {
                        "type": "event",
                        "method": "property",
                        "property_name": "context",
                        "property_type": "list",
                        "command": {
                            "type": "query",
                            "source": "splunk",
                            "query": "search context lookup",
                            "time_range": {"before": "1h", "after": "1h"},
                        },
                    },
                },
            ],
        }
        config = CorrelateConfig.model_validate(config_data)
        engine = CorrelationEngine(
            config, [], datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
            hunt_source_type="splunk",
        )

        events = [{"_time": "2024-06-01T12:00:00+00:00", "host": "web1"}]
        result = engine.execute(events)

        assert len(splunk.calls) == 1
        ref = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        # window anchored to the event's _time (NOT the hunt window of 2099) proves defaults applied
        assert splunk.calls[0]["start_time"] == ref - datetime.timedelta(hours=1)
        assert splunk.calls[0]["end_time"] == ref + datetime.timedelta(hours=1)
        assert result.events[0]["context"] == [{"matched": True}]
