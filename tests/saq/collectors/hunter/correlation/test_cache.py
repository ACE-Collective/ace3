from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.cache import (
    CorrelateQueryRecorder,
    _describe_command,
    _make_cache_key,
    get_cached_result,
    set_cached_result,
)


@pytest.mark.unit
class TestCacheKeyGeneration:

    def test_deterministic(self):
        args = {"type": "query", "source": "splunk", "query": "index=main"}
        key1 = _make_cache_key(args)
        key2 = _make_cache_key(args)
        assert key1 == key2

    def test_different_args_different_keys(self):
        key1 = _make_cache_key({"query": "a"})
        key2 = _make_cache_key({"query": "b"})
        assert key1 != key2

    def test_key_format(self):
        key = _make_cache_key({"test": "value"})
        assert key.startswith("hunt_cache:")
        assert len(key) == len("hunt_cache:") + 64  # sha256 hex digest


@pytest.mark.unit
class TestDescribeCommand:

    def test_query_summary_collapses_whitespace(self):
        desc = _describe_command({
            "type": "query",
            "source": "logscale",
            "query": "ComputerName=/x/i\n  | foo   bar",
        })
        assert desc == "type=query source=logscale query='ComputerName=/x/i | foo bar'"

    def test_query_summary_truncates_long_query(self):
        desc = _describe_command({"type": "query", "source": "splunk", "query": "a" * 500})
        assert desc.endswith("…'")
        assert len(desc) < 400

    def test_executable_summary(self):
        desc = _describe_command({"type": "executable", "path": "/bin/foo", "args": ["-c", "x"]})
        assert desc == "type=executable path=/bin/foo args=['-c', 'x']"

    def test_executable_summary_omits_env(self):
        """env can hold a credential (it is the one context bound to _secrets) and this
        description is written to the log, so it must never appear here."""
        desc = _describe_command({
            "type": "executable",
            "path": "/bin/foo",
            "args": ["-c", "x"],
            "env": {"API_KEY": "REAL_KEY"},
        })
        assert "REAL_KEY" not in desc
        assert "API_KEY" not in desc

    def test_unknown_type(self):
        assert _describe_command({}) == "type=?"


@pytest.mark.unit
class TestCacheOperations:

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_get_cached_hit(self, mock_get_redis):
        mock_redis = MagicMock()
        mock_redis.get.return_value = "cached_output"
        mock_get_redis.return_value = mock_redis

        result = get_cached_result({"query": "test"})
        assert result == "cached_output"

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_get_cached_miss(self, mock_get_redis):
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        mock_get_redis.return_value = mock_redis

        result = get_cached_result({"query": "test"})
        assert result is None

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_set_cached(self, mock_get_redis):
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis

        set_cached_result({"query": "test"}, "output", 3600)
        mock_redis.setex.assert_called_once()

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_set_cached_logs_command_identity(self, mock_get_redis, caplog):
        mock_get_redis.return_value = MagicMock()

        import logging
        with caplog.at_level(logging.INFO):
            set_cached_result(
                {"type": "query", "source": "logscale", "query": "index=main"},
                "output",
                300,
            )

        # the log line must identify what was cached (source + query), not just the hash
        assert "source=logscale" in caplog.text
        assert "index=main" in caplog.text
        assert "for 300s" in caplog.text

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_set_cached_redacts_secrets(self, mock_get_redis, caplog):
        mock_get_redis.return_value = MagicMock()

        import logging
        with caplog.at_level(logging.INFO):
            set_cached_result(
                {"type": "query", "source": "splunk", "query": "token=SUPERSECRET index=main"},
                "output",
                300,
                {"api_key": "SUPERSECRET"},
            )

        assert "SUPERSECRET" not in caplog.text
        assert "***" in caplog.text

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_get_cached_hit_logs_command_identity(self, mock_get_redis, caplog):
        mock_redis = MagicMock()
        mock_redis.get.return_value = "cached_output"
        mock_get_redis.return_value = mock_redis

        import logging
        with caplog.at_level(logging.INFO):
            get_cached_result({"type": "query", "source": "logscale", "query": "index=main"})

        assert "cache hit" in caplog.text
        assert "source=logscale" in caplog.text

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_get_handles_redis_error(self, mock_get_redis):
        mock_get_redis.side_effect = Exception("connection error")
        result = get_cached_result({"query": "test"})
        assert result is None

    @patch("saq.collectors.hunter.correlation.cache.get_redis_connection")
    def test_set_handles_redis_error(self, mock_get_redis):
        mock_get_redis.side_effect = Exception("connection error")
        # Should not raise
        set_cached_result({"query": "test"}, "output", 3600)


@pytest.mark.unit
class TestCorrelateQueryRecorder:

    def test_capture_export_roundtrip(self):
        recorder = CorrelateQueryRecorder()
        assert recorder.replay_active is False
        recorder.record("splunk", "search index=main", '{"host": "web1"}\n{"host": "web2"}')
        exported = recorder.export()
        assert exported == [{
            "source": "splunk",
            "query": "search index=main",
            "results": [{"host": "web1"}, {"host": "web2"}],
        }]

    def test_replay_lookup_hit_and_miss(self):
        recorder = CorrelateQueryRecorder(replay=[
            {"source": "splunk", "query": "search index=main", "results": [{"host": "web1"}]},
        ])
        assert recorder.replay_active is True
        # hit returns the JSONL string _execute_query expects
        assert recorder.lookup("splunk", "search index=main") == '{"host": "web1"}'
        # miss on a different rendered query / source
        assert recorder.lookup("splunk", "search index=other") is None
        assert recorder.lookup("logscale", "search index=main") is None

    def test_record_dedup_first_wins(self):
        recorder = CorrelateQueryRecorder()
        recorder.record("splunk", "q", '{"a": 1}')
        recorder.record("splunk", "q", '{"a": 2}')
        exported = recorder.export()
        assert len(exported) == 1
        assert exported[0]["results"] == [{"a": 1}]

    def test_replay_then_export_is_complete(self):
        """A round-trip: a recorder seeded for replay, whose hits are recorded, exports
        the same records — so re-saving after an offline run keeps the file complete."""
        saved = [
            {"source": "splunk", "query": "q1", "results": [{"x": 1}]},
            {"source": "splunk", "query": "q2", "results": [{"y": 2}]},
        ]
        recorder = CorrelateQueryRecorder(replay=saved)
        for record in saved:
            output = recorder.lookup(record["source"], record["query"])
            recorder.record(record["source"], record["query"], output)
        assert recorder.export() == saved

    def test_empty_replay_is_inactive(self):
        assert CorrelateQueryRecorder(replay=[]).replay_active is False
        assert CorrelateQueryRecorder(replay=None).replay_active is False
