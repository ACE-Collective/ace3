"""Tests for bin/run-cron-job, the wrapper that gives every scheduled job a structured
outcome record.

The wrapper sits in the job's execution path, so the load-bearing property is that it
passes the child's exit code through untouched no matter what the reporting side does.
Everything else here guards the log-file behaviour the old shell redirect provided.
"""

import importlib.machinery
import importlib.util
import os
import socket
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

RUNNER_PATH = Path(__file__).resolve().parents[2] / "bin" / "run-cron-job"


def _load_runner():
    # bin/run-cron-job has no .py extension, so spec_from_file_location cannot infer a
    # loader on its own and returns None -- name the loader explicitly.
    loader = importlib.machinery.SourceFileLoader("run_cron_job", str(RUNNER_PATH))
    spec = importlib.util.spec_from_file_location("run_cron_job", RUNNER_PATH, loader=loader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def runner(tmp_path, monkeypatch):
    """the wrapper, with SAQ_HOME pointed at a temp dir so it writes nowhere real

    Loading it here also asserts the module imports at all -- and it must stay
    stdlib-only at module scope, because importing anything from saq costs ~2.4s and this
    runs after every cron job.
    """
    module = _load_runner()
    monkeypatch.setattr(module, "SAQ_HOME", str(tmp_path))
    return module


@pytest.fixture
def sender(runner):
    """patches fluent.sender.FluentSender

    the wrapper imports fluent lazily inside emit(), so the patch target is the fluent
    package itself rather than an attribute on the wrapper (unlike tests/saq/test_monitor.py,
    which patches saq.monitor.sender.FluentSender because that module imports it up top)
    """
    with patch("fluent.sender.FluentSender") as sender_class:
        instance = MagicMock()
        instance.emit.return_value = True
        sender_class.return_value = instance
        sender_class.instance = instance
        yield sender_class


def emitted_record(sender):
    """the single record passed to FluentSender.emit()"""
    assert sender.instance.emit.call_count == 1
    args, _ = sender.instance.emit.call_args
    assert args[0] is None
    return args[1]


def log_contents(runner, slug):
    return Path(runner.log_file_path(slug)).read_bytes()


@pytest.mark.unit
class TestExitCodeContract:
    """the wrapper must never change the outcome of the job it runs"""

    def test_returns_child_exit_code_on_success(self, runner, sender):
        assert runner.main(["run-cron-job", "job", "/bin/true"]) == 0

    def test_returns_child_exit_code_on_failure(self, runner, sender):
        assert runner.main(["run-cron-job", "job", "/bin/sh", "-c", "exit 3"]) == 3

    def test_emit_failure_does_not_change_exit_code(self, runner, sender):
        """a broken or unreachable fluent-bit must not turn a job into a failure"""
        sender.side_effect = ConnectionRefusedError("no fluent-bit here")

        assert runner.main(["run-cron-job", "job", "/bin/sh", "-c", "exit 3"]) == 3

    def test_emit_returning_false_does_not_change_exit_code(self, runner, sender):
        """fluent-logger signals a soft failure by returning False rather than raising"""
        sender.instance.emit.return_value = False

        assert runner.main(["run-cron-job", "job", "/bin/true"]) == 0

    def test_unlaunchable_command_returns_127_and_reports_error(self, runner, sender):
        assert runner.main(["run-cron-job", "job", "/nonexistent/xyz"]) == 127

        record = emitted_record(sender)
        assert record["exit_code"] == 127
        assert record["success"] is False
        assert "error" in record
        assert b"unable to execute" in log_contents(runner, "job")

    @pytest.mark.parametrize("argv", [["run-cron-job"], ["run-cron-job", "slug"]])
    def test_missing_arguments_returns_2(self, runner, sender, argv):
        assert runner.main(argv) == 2
        assert sender.instance.emit.call_count == 0


@pytest.mark.unit
class TestLogFile:
    """the wrapper owns the per-day log file the shell redirect used to produce"""

    def test_writes_stdout_and_stderr_to_log_file(self, runner, sender):
        runner.main(["run-cron-job", "job", "/bin/sh", "-c", "echo to-stdout; echo to-stderr >&2"])

        contents = log_contents(runner, "job")
        assert b"to-stdout" in contents
        assert b"to-stderr" in contents

    def test_appends_to_existing_log_file(self, runner, sender):
        """regression test for the >> semantics -- a second run must not truncate"""
        path = Path(runner.log_file_path("job"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"earlier run\n")

        runner.main(["run-cron-job", "job", "/bin/echo", "later run"])

        contents = path.read_bytes()
        assert contents.index(b"earlier run") < contents.index(b"later run")

    def test_creates_log_directory_if_missing(self, runner, sender, tmp_path):
        assert not (tmp_path / "data" / "logs").exists()

        runner.main(["run-cron-job", "job", "/bin/true"])

        assert Path(runner.log_file_path("job")).exists()

    def test_log_file_path_uses_slug_and_date(self, runner, tmp_path):
        """the exact filename shape etc/logrotate.conf and daily-maintenance.sh rotate"""
        path = runner.log_file_path("daily-maintenance", datetime(2026, 9, 3, 5, 0, 0))

        assert path == str(tmp_path / "data" / "logs" / "daily-maintenance-2026-09-03.log")


@pytest.mark.unit
class TestRecord:
    def test_success_record_fields(self, runner, sender):
        runner.main(["run-cron-job", "export-observables", "/bin/echo", "hi"])

        record = emitted_record(sender)
        assert record["job"] == "export-observables"
        assert record["command"] == "/bin/echo hi"
        assert record["exit_code"] == 0
        assert record["success"] is True
        assert record["severity"] == "INFO"
        assert record["log_file"] == runner.log_file_path("export-observables")
        assert record["duration_seconds"] >= 0
        # must be parseable -- alerting keys off this
        datetime.fromisoformat(record["timestamp"])

    def test_failure_record_severity_and_success_flag(self, runner, sender):
        runner.main(["run-cron-job", "job", "/bin/false"])

        record = emitted_record(sender)
        assert record["success"] is False
        assert record["severity"] == "ERROR"
        assert record["exit_code"] == 1

    def test_output_tail_present_only_on_failure(self, runner, sender):
        runner.main(["run-cron-job", "job", "/bin/echo", "quiet success"])
        assert "output_tail" not in emitted_record(sender)

        sender.instance.emit.reset_mock()
        runner.main(["run-cron-job", "job", "/bin/sh", "-c", "echo boom >&2; exit 1"])
        assert "boom" in emitted_record(sender)["output_tail"]

    def test_output_tail_is_truncated_to_the_last_bytes(self, runner, sender):
        """guards the seek-from-end arithmetic -- we want the end, not the beginning"""
        script = "for i in $(seq 1 5000); do echo LINE$i; done; exit 1"
        runner.main(["run-cron-job", "job", "/bin/sh", "-c", script])

        tail = emitted_record(sender)["output_tail"]
        assert len(tail.encode()) <= runner.FAILURE_OUTPUT_TAIL_BYTES
        assert "LINE5000" in tail
        assert "LINE1\n" not in tail

    def test_output_tail_survives_undecodable_bytes(self, runner, sender):
        runner.main(["run-cron-job", "job", "/bin/sh", "-c", "printf '\\377\\376'; exit 1"])

        assert "�" in emitted_record(sender)["output_tail"]

    def test_read_tail_on_missing_file_returns_placeholder(self, runner, tmp_path):
        result = runner.read_tail(str(tmp_path / "nope.log"), 4096)

        assert result.startswith("<unable to read ")

    def test_duration_is_recorded(self, runner, sender):
        runner.main(["run-cron-job", "job", "/bin/sh", "-c", "sleep 0.2"])

        assert 0.1 <= emitted_record(sender)["duration_seconds"] < 30

    def test_node_prefers_saq_node_env(self, runner, sender, monkeypatch):
        monkeypatch.setenv("SAQ_NODE", "node-a")

        runner.main(["run-cron-job", "job", "/bin/true"])

        assert emitted_record(sender)["node"] == "node-a"

    def test_node_falls_back_to_hostname(self, runner, sender, monkeypatch):
        monkeypatch.delenv("SAQ_NODE", raising=False)

        runner.main(["run-cron-job", "job", "/bin/true"])

        assert emitted_record(sender)["node"] == socket.gethostname()


@pytest.mark.unit
class TestEmitter:
    def test_sender_constructed_with_expected_tag_host_port(self, runner, sender):
        """pins the tag that etc/fluent-bit/fluent-bit.yaml matches on"""
        runner.main(["run-cron-job", "job", "/bin/true"])

        args, kwargs = sender.call_args
        assert args[0] == "cron-jobs"
        assert kwargs["host"] == runner.FLUENT_BIT_HOST
        assert kwargs["port"] == runner.FLUENT_BIT_PORT

    def test_host_and_port_are_environment_overridable(self, runner, monkeypatch):
        monkeypatch.setenv("FLUENT_BIT_HOST", "collector.example")
        monkeypatch.setenv("FLUENT_BIT_PORT", "9999")

        reloaded = _load_runner()

        assert reloaded.FLUENT_BIT_HOST == "collector.example"
        assert reloaded.FLUENT_BIT_PORT == 9999

    def test_sender_is_closed_even_when_emit_raises(self, runner, sender):
        sender.instance.emit.side_effect = RuntimeError("boom")

        assert runner.main(["run-cron-job", "job", "/bin/true"]) == 0
        sender.instance.close.assert_called_once()
