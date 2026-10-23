"""Tests for the CLI commands that only hand off to a library function:
`ace cron`, `ace cache`, `ace nrd`, `ace observables` and `ace submit`."""

import hashlib
import os

import pytest

import ace_api
import saq.cli.commands.cache  # registers the commands
import saq.cli.commands.cron  # registers the commands
import saq.cli.commands.nrd  # registers the commands
import saq.cli.commands.observables  # registers the commands
import saq.cli.commands.submit  # registers the commands
import saq.cron_tasks
import saq.nrd.refresh
import saq.observables.export.manager
import saq.util.maintenance
from saq.cli.cli_main import get_cli_parser
from saq.constants import F_FILE, F_IPV4


def _parse(*argv):
    return get_cli_parser().parse_args(list(argv))


def _ace(*argv) -> int:
    args = _parse(*argv)
    with pytest.raises(SystemExit) as e:
        args.func(args)

    return e.value.code


@pytest.mark.unit
@pytest.mark.parametrize("argv, expected", [
    (["daily"], ("daily", None)),
    (["hourly", "--max-parallel", "3"], ("hourly", 3)),
])
def test_cron_run(monkeypatch, argv, expected):
    calls = []
    monkeypatch.setattr(saq.cron_tasks, "run_tasks", lambda cadence, max_parallel: calls.append((cadence, max_parallel)) or 1)

    # the exit code is the one run_tasks returned
    assert _ace("cron", "run", *argv) == 1
    assert calls == [expected]


@pytest.mark.unit
@pytest.mark.parametrize("value", ["0", "-1", "x"])
def test_cron_run_rejects_a_max_parallel_below_one(value, capsys):
    with pytest.raises(SystemExit) as e:
        _parse("cron", "run", "daily", "--max-parallel", value)

    assert e.value.code == 2
    assert "invalid _positive_int value" in capsys.readouterr().err


@pytest.mark.unit
def test_cron_list(capsys):
    assert _ace("cron", "list", "daily") == 0

    out = capsys.readouterr().out
    for task in saq.cron_tasks.discover_tasks("daily"):
        assert task.slug in out
        assert task.path in out


@pytest.mark.unit
@pytest.mark.parametrize("argv, function, kwargs", [
    (["stats"], "emit_cache_stats", {}),
    (["gc"], "gc_durable_blobs", {"dry_run": False}),
    (["gc", "--dry-run"], "gc_durable_blobs", {"dry_run": True}),
    (["local-maintenance"], "maintain_local_cache", {"dry_run": False}),
    (["local-maintenance", "--dry-run"], "maintain_local_cache", {"dry_run": True}),
])
def test_cache_commands(monkeypatch, argv, function, kwargs):
    calls = []
    monkeypatch.setattr(saq.util.maintenance, function, lambda **kw: calls.append(kw))

    assert _ace("cache", *argv) == 0
    assert calls == [kwargs]


@pytest.mark.unit
def test_nrd_refresh_exits_with_the_refresh_result(monkeypatch):
    monkeypatch.setattr(saq.nrd.refresh, "refresh", lambda: 3)

    assert _ace("nrd", "refresh") == 3


@pytest.mark.unit
@pytest.mark.parametrize("argv, expected", [
    ([], ([], False)),
    (["splunk", "edr", "--force"], (["splunk", "edr"], True)),
])
def test_observables_export(monkeypatch, argv, expected):
    calls = []
    monkeypatch.setattr(saq.observables.export.manager, "run_exports",
                        lambda systems, force: calls.append((systems, force)) or 0)

    assert _ace("observables", "export", *argv) == 0
    assert calls == [expected]


@pytest.fixture
def submissions(monkeypatch):
    calls = []
    monkeypatch.setattr(ace_api, "submit", lambda **kwargs: calls.append(kwargs))
    return calls


@pytest.mark.unit
def test_submit_defaults(submissions):
    args = _parse("submit", F_IPV4, "192.0.2.1")

    assert args.func(args) == os.EX_OK
    assert submissions == [{
        "description": "ACE Manual Correlation", "analysis_mode": "analysis", "queue": "default",
        "observables": [{"type": F_IPV4, "value": "192.0.2.1"}], "files": [], "remote_host": "ace-http"}]


@pytest.mark.unit
def test_submit_file_and_options(submissions, tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"sample content")
    args = _parse("submit", "-d", "manual test", "-m", "correlation", "--queue", "external",
                  "--remote-host", "ace.example.com", F_FILE, str(path), F_IPV4, "192.0.2.1")

    assert args.func(args) == os.EX_OK
    [submission] = submissions
    assert submission["description"] == "manual test"
    assert submission["analysis_mode"] == "correlation"
    assert submission["queue"] == "external"
    assert submission["remote_host"] == "ace.example.com"
    assert submission["observables"] == [
        {"type": F_FILE, "value": hashlib.sha256(b"sample content").hexdigest(), "file_path": "sample.bin"},
        {"type": F_IPV4, "value": "192.0.2.1"},
    ]
    [(name, fp)] = submission["files"]
    assert name == "sample.bin"
    assert fp.read() == b"sample content"
    fp.close()


@pytest.mark.unit
def test_submit_odd_number_of_targets_is_a_usage_error(submissions, capsys):
    args = _parse("submit", F_IPV4)

    assert args.func(args) == os.EX_USAGE
    assert "targets must be pairs of indicator types and values" in capsys.readouterr().out
    assert submissions == []
