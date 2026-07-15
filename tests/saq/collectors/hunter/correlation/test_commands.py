import datetime
import json
import sys
from unittest.mock import patch

import pytest

from saq.collectors.hunter.correlation.cache import CorrelateQueryRecorder
from saq.collectors.hunter.correlation.commands import _resolve_time_range, execute_command
from saq.collectors.hunter.correlation.registry import (
    QuerySource,
    clear_query_sources,
    register_query_source,
)
from saq.collectors.hunter.correlation.schema import CommandConfig, PredefinedCommandConfig, TimeRangeConfig
from saq.util import local_time

PYTHON = sys.executable


class MockQuerySource(QuerySource):
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
        return self.results


class MockEpochSource(QuerySource):
    """Source whose default field/format differ from MockQuerySource for switching tests."""
    default_time_field = "ts"
    default_time_format = "epoch"

    def execute_query(self, query, start_time, end_time, timeout, source_options=None):
        return []


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_query_sources()
    yield
    clear_query_sources()


@pytest.mark.unit
class TestExecuteCommand:

    def test_query_command(self, tmpdir):
        source = MockQuerySource(results=[{"host": "web1"}, {"host": "web2"}])
        register_query_source("test_source", source)

        cmd = CommandConfig(
            type="query",
            source="test_source",
            query="search index=main",
            time_range=None,
        )

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            result = execute_command(
                cmd, {}, [], "event", [], local_time(), str(tmpdir),
            )

        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"host": "web1"}

    def test_query_command_forwards_source_options(self, tmpdir):
        """source_options from the YAML must reach the QuerySource verbatim."""
        source = MockQuerySource(results=[])
        register_query_source("test_source", source)

        cmd = CommandConfig(
            type="query",
            source="test_source",
            query="where(host='{{ _event.host }}')",
            source_options={"log_names": ["Firewall Activity", "DNS Activity"]},
        )

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(cmd, {"host": "web1"}, [], "event", [], local_time(), str(tmpdir))

        assert len(source.calls) == 1
        assert source.calls[0]["source_options"] == {
            "log_names": ["Firewall Activity", "DNS Activity"],
        }

    def test_query_command_omitted_source_options_is_empty_dict(self, tmpdir):
        """When the YAML omits source_options, the source receives an empty dict."""
        source = MockQuerySource(results=[])
        register_query_source("test_source", source)

        cmd = CommandConfig(
            type="query",
            source="test_source",
            query="search index=main",
        )

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert source.calls[0]["source_options"] == {}

    def test_executable_command(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello world')"],
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() == "hello world"

    def test_executable_with_jinja_args(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import sys; print(sys.argv[1], sys.argv[2])", "{{ _event.user }}", "{{ _event.host }}"],
        )
        result = execute_command(
            cmd, {"user": "admin", "host": "web1"}, [], "event", [], local_time(), str(tmpdir),
        )
        assert result.strip() == "admin web1"

    def test_executable_with_stdin_event(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import sys; print(sys.stdin.read(), end='')"],
            stdin=True,
        )
        event = {"user": "admin"}
        result = execute_command(cmd, event, [event], "event", [], local_time(), str(tmpdir))
        assert json.loads(result) == {"user": "admin"}

    def test_defined_command(self, tmpdir):
        predef = PredefinedCommandConfig(
            name="lookup",
            type="executable",
            path=PYTHON,
            args=["-c", "print('default')"],
        )

        cmd = CommandConfig(
            type="defined",
            name="lookup",
            arguments={"args": ["-c", "import sys; print(sys.argv[1])", "{{ _event.user }}"]},
        )
        result = execute_command(
            cmd, {"user": "admin"}, [], "event", [predef], local_time(), str(tmpdir),
        )
        assert result.strip() == "admin"

    def test_defined_command_not_found(self, tmpdir):
        cmd = CommandConfig(type="defined", name="nonexistent")
        with pytest.raises(ValueError, match="not found"):
            execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

    def test_stream_query_memoization(self, tmpdir):
        source = MockQuerySource(results=[{"host": "web1"}])
        register_query_source("test_source", source)

        cmd = CommandConfig(type="query", source="test_source", query="search index=main")
        cache = {}

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            result1 = execute_command(cmd, {}, [], "stream", [], local_time(), str(tmpdir), cache)
            result2 = execute_command(cmd, {}, [], "stream", [], local_time(), str(tmpdir), cache)

        assert result1 == result2
        assert len(source.calls) == 1  # only called once

    def test_executable_with_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ['MY_VAR'])"],
            env={"MY_VAR": "hello"},
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() == "hello"

    def test_executable_with_jinja_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ['USER_NAME'])"],
            env={"USER_NAME": "{{ _event.user }}"},
        )
        result = execute_command(
            cmd, {"user": "admin"}, [], "event", [], local_time(), str(tmpdir),
        )
        assert result.strip() == "admin"

    def test_executable_with_env_inherits_os_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ.get('PATH', 'missing'))"],
            env={"MY_VAR": "test"},
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() != "missing"

    def test_executable_without_env_inherits_os_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ.get('PATH', 'missing'))"],
        )
        result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))
        assert result.strip() != "missing"

    def test_executable_timeout(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import time; time.sleep(60)"],
            timeout="1s",
        )
        with pytest.raises(RuntimeError, match="timed out"):
            execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

    def test_executable_cache_hit(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')"],
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value="cached value") as mock_get:
            result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert result == "cached value"
        mock_get.assert_called_once_with({"type": "executable", "path": PYTHON, "args": ["-c", "print('hello')"], "env": None})

    def test_executable_cache_miss_stores_result(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')"],
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result") as mock_set:
            result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert result.strip() == "hello"
        mock_set.assert_called_once_with(
            {"type": "executable", "path": PYTHON, "args": ["-c", "print('hello')"], "env": None},
            result,
            3600,
        )

    def test_executable_no_cache_skips_cache(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')"],
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result") as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result") as mock_set:
            result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert result.strip() == "hello"
        mock_get.assert_not_called()
        mock_set.assert_not_called()

    def test_executable_cache_key_includes_rendered_args(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "print('hello')", "{{ _event.user }}"],
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None) as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(cmd, {"user": "admin"}, [], "event", [], local_time(), str(tmpdir))

        mock_get.assert_called_once_with({"type": "executable", "path": PYTHON, "args": ["-c", "print('hello')", "admin"], "env": None})

    def test_executable_cache_key_includes_rendered_env(self, tmpdir):
        cmd = CommandConfig(
            type="executable",
            path=PYTHON,
            args=["-c", "import os; print(os.environ['MY_VAR'])"],
            env={"MY_VAR": "{{ _event.val }}"},
            cache="1h",
        )
        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None) as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(cmd, {"val": "test123"}, [], "event", [], local_time(), str(tmpdir))

        mock_get.assert_called_once_with({
            "type": "executable",
            "path": PYTHON,
            "args": ["-c", "import os; print(os.environ['MY_VAR'])"],
            "env": {"MY_VAR": "test123"},
        })

    def test_query_cache_hit(self, tmpdir):
        source = MockQuerySource(results=[{"host": "should-not-run"}])
        register_query_source("test_source", source)

        cmd = CommandConfig(type="query", source="test_source", query="search index=main", cache="5m")

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value="cached value") as mock_get:
            result = execute_command(cmd, {}, [], "event", [], local_time(), str(tmpdir))

        assert result == "cached value"
        # a cache hit must short-circuit before the data source is touched
        assert len(source.calls) == 0
        mock_get.assert_called_once_with({"type": "query", "source": "test_source", "query": "search index=main"})

    def test_query_cache_key_includes_rendered_query(self, tmpdir):
        """The persistent cache must key on the interpolated query, not the raw template."""
        source = MockQuerySource(results=[{"animal": "dog", "count": "10"}])
        register_query_source("test_source", source)

        cmd = CommandConfig(
            type="query",
            source="test_source",
            query='search animal="{{ _event.animal }}"',
            cache="5m",
        )

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None) as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result") as mock_set:
            execute_command(cmd, {"animal": "dog"}, [], "event", [], local_time(), str(tmpdir))

        expected_args = {"type": "query", "source": "test_source", "query": 'search animal="dog"'}
        mock_get.assert_called_once_with(expected_args)
        mock_set.assert_called_once()
        assert mock_set.call_args.args[0] == expected_args

    def test_query_different_events_different_cache_keys(self, tmpdir):
        """Regression: two events with the same template but different interpolated
        values must produce different cache keys (otherwise the first event's result
        is served to every later event)."""
        source = MockQuerySource(results=[])
        register_query_source("test_source", source)

        cmd = CommandConfig(
            type="query",
            source="test_source",
            query='search animal="{{ _event.animal }}"',
            cache="5m",
        )

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None) as mock_get, \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(cmd, {"animal": "dog"}, [], "event", [], local_time(), str(tmpdir))
            execute_command(cmd, {"animal": "cat"}, [], "event", [], local_time(), str(tmpdir))

        queried = [call.args[0]["query"] for call in mock_get.call_args_list]
        assert queried == ['search animal="dog"', 'search animal="cat"']
        assert queried[0] != queried[1]


@pytest.mark.unit
class TestResolveTimeRange:

    def _make_query_command(self, time_range=None):
        return CommandConfig(
            type="query",
            source="splunk",
            query="search index=main",
            time_range=time_range,
        )

    def test_explicit_field_and_format_override_defaults(self):
        register_query_source("splunk", MockQuerySource())
        cmd = self._make_query_command(
            time_range=TimeRangeConfig(
                before="1h", after="1h",
                relative_time_field="custom", relative_time_format="iso8601",
            ),
        )
        event = {"custom": "2024-06-01T00:00:00+00:00", "_time": "2099-01-01T00:00:00+00:00"}
        start, end = _resolve_time_range(cmd, event, "event", local_time(), local_time(), "splunk")
        # reference time should come from `custom`, not `_time`
        assert start == datetime.datetime(2024, 5, 31, 23, 0, tzinfo=datetime.timezone.utc)
        assert end == datetime.datetime(2024, 6, 1, 1, 0, tzinfo=datetime.timezone.utc)

    def test_default_field_and_format_used_when_omitted(self):
        register_query_source("splunk", MockQuerySource())
        cmd = self._make_query_command(time_range=TimeRangeConfig(before="30m", after="30m"))
        event = {"_time": "2024-06-01T12:00:00+00:00"}
        start, end = _resolve_time_range(cmd, event, "event", local_time(), local_time(), "splunk")
        assert start == datetime.datetime(2024, 6, 1, 11, 30, tzinfo=datetime.timezone.utc)
        assert end == datetime.datetime(2024, 6, 1, 12, 30, tzinfo=datetime.timezone.utc)

    def test_explicit_format_with_default_field(self):
        register_query_source("splunk", MockQuerySource())
        cmd = self._make_query_command(
            time_range=TimeRangeConfig(before="1h", after="0s", relative_time_format="epoch"),
        )
        # use the default field `_time` but override the format to epoch
        event = {"_time": "1717200000"}
        start, end = _resolve_time_range(cmd, event, "event", local_time(), local_time(), "splunk")
        ref = datetime.datetime.fromtimestamp(1717200000, tz=datetime.timezone.utc)
        assert end == ref
        assert start == ref - datetime.timedelta(hours=1)

    def test_explicit_field_with_default_format(self):
        register_query_source("splunk", MockQuerySource())
        cmd = self._make_query_command(
            time_range=TimeRangeConfig(before="0s", after="1h", relative_time_field="when"),
        )
        # default format from splunk source is iso8601
        event = {"when": "2024-06-01T00:00:00+00:00"}
        start, end = _resolve_time_range(cmd, event, "event", local_time(), local_time(), "splunk")
        ref = datetime.datetime(2024, 6, 1, 0, 0, tzinfo=datetime.timezone.utc)
        assert start == ref
        assert end == ref + datetime.timedelta(hours=1)

    def test_missing_default_field_raises(self):
        register_query_source("splunk", MockQuerySource())
        cmd = self._make_query_command(time_range=TimeRangeConfig(before="30m", after="30m"))
        event = {"host": "web1"}  # no _time
        with pytest.raises(KeyError, match="_time"):
            _resolve_time_range(cmd, event, "event", local_time(), local_time(), "splunk")

    def test_no_current_source_falls_back_to_hunt_window(self):
        # no source registered, no current_source supplied -> no resolvable field ->
        # anchor to the hunt's query window: before -> start, after -> end
        cmd = self._make_query_command(time_range=TimeRangeConfig(before="1h", after="2h"))
        hunt_start = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        hunt_end = datetime.datetime(2024, 6, 1, 18, 0, tzinfo=datetime.timezone.utc)
        event = {"host": "web1"}
        start, end = _resolve_time_range(cmd, event, "event", hunt_start, hunt_end, None)
        assert start == hunt_start - datetime.timedelta(hours=1)
        assert end == hunt_end + datetime.timedelta(hours=2)

    def test_unknown_current_source_falls_back_to_hunt_window(self):
        # current_source given but not registered -> no defaults, no field in YAML ->
        # anchor to the hunt's query window
        cmd = self._make_query_command(time_range=TimeRangeConfig(before="1h", after="2h"))
        hunt_start = datetime.datetime(2024, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
        hunt_end = datetime.datetime(2024, 6, 1, 18, 0, tzinfo=datetime.timezone.utc)
        event = {"host": "web1"}
        start, end = _resolve_time_range(cmd, event, "event", hunt_start, hunt_end, "not_registered")
        assert start == hunt_start - datetime.timedelta(hours=1)
        assert end == hunt_end + datetime.timedelta(hours=2)

    def test_stream_transform_anchors_to_hunt_window(self):
        # stream transforms ignore per-event time fields and anchor a relative
        # time_range to the hunt's query window: before -> window start, after -> window end
        register_query_source("splunk", MockQuerySource())
        cmd = self._make_query_command(time_range=TimeRangeConfig(before="3h", after="1h"))
        hunt_start = datetime.datetime(2024, 6, 1, 0, 0, tzinfo=datetime.timezone.utc)
        hunt_end = datetime.datetime(2024, 6, 2, 0, 0, tzinfo=datetime.timezone.utc)
        # the event has a time field, but a stream transform must NOT anchor to it
        event = {"_time": "2099-01-01T00:00:00+00:00"}
        start, end = _resolve_time_range(cmd, event, "stream", hunt_start, hunt_end, "splunk")
        assert start == hunt_start - datetime.timedelta(hours=3)
        assert end == hunt_end + datetime.timedelta(hours=1)


@pytest.mark.unit
class TestQueryRecorder:
    """Capture/replay of rendered correlate query results via CorrelateQueryRecorder."""

    def _cmd(self):
        # rendered query differs per event (interpolates _event.host), like the azure hunt
        return CommandConfig(
            type="query",
            source="test_source",
            query="search host={{ _event.host }}",
            time_range=None,
        )

    def test_replay_hit_skips_live_query(self, tmpdir):
        source = MockQuerySource(results=[{"should": "not be used"}])
        register_query_source("test_source", source)
        recorder = CorrelateQueryRecorder(replay=[
            {"source": "test_source", "query": "search host=web1", "results": [{"host": "web1", "saved": True}]},
        ])

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            result = execute_command(
                self._cmd(), {"host": "web1"}, [], "event", [], local_time(), str(tmpdir),
                query_recorder=recorder,
            )

        assert json.loads(result) == {"host": "web1", "saved": True}
        assert len(source.calls) == 0  # data source never hit on a replay hit

    def test_replay_miss_falls_back_to_live_and_records(self, tmpdir):
        source = MockQuerySource(results=[{"host": "web2", "live": True}])
        register_query_source("test_source", source)
        # replay seeded, but for a different rendered query -> miss -> live + warn
        recorder = CorrelateQueryRecorder(replay=[
            {"source": "test_source", "query": "search host=web1", "results": [{"host": "web1"}]},
        ])

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            result = execute_command(
                self._cmd(), {"host": "web2"}, [], "event", [], local_time(), str(tmpdir),
                query_recorder=recorder,
            )

        assert json.loads(result) == {"host": "web2", "live": True}
        assert len(source.calls) == 1
        assert source.calls[0]["query"] == "search host=web2"
        # the live result is captured under its rendered query, keyed alongside replay
        exported = {r["query"]: r["results"] for r in recorder.export()}
        assert exported["search host=web2"] == [{"host": "web2", "live": True}]

    def test_pure_capture_records_rendered_query(self, tmpdir):
        source = MockQuerySource(results=[{"host": "web3"}])
        register_query_source("test_source", source)
        recorder = CorrelateQueryRecorder()  # no replay -> pure capture

        with patch("saq.collectors.hunter.correlation.commands.get_cached_result", return_value=None), \
             patch("saq.collectors.hunter.correlation.commands.set_cached_result"):
            execute_command(
                self._cmd(), {"host": "web3"}, [], "event", [], local_time(), str(tmpdir),
                query_recorder=recorder,
            )

        assert len(source.calls) == 1
        assert recorder.export() == [
            {"source": "test_source", "query": "search host=web3", "results": [{"host": "web3"}]},
        ]
