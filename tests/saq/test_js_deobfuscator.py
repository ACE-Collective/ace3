"""Tests for the js-deobfuscator manager's tasks, ACE's client and `ace js-deobfuscator`."""

import logging
import os
import time
from types import SimpleNamespace

import pytest

import js_deobfuscator.js_deobfuscator as manager
import saq.cli.commands.js_deobfuscator as js_deobfuscator_cli
import saq.js_deobfuscator
from saq.cli.cli_main import get_cli_parser
from saq.configuration.config import get_config
from saq.js_deobfuscator import deobfuscate_file, maintain_files

DAY = 86400


# stands in for the broker the manager's module builds its app with, the one the manager consumes from
MANAGER_BROKER = "pyamqp://ace3:manager-pass@rabbitmq//"


@pytest.fixture
def divergent_rabbitmq_config(monkeypatch):
    """A rabbitmq configuration that names another broker than the manager's."""
    rabbitmq = get_config().rabbitmq
    monkeypatch.setattr(rabbitmq, "username", "jd-user")
    monkeypatch.setattr(rabbitmq, "password", "jd-pass")
    monkeypatch.setattr(rabbitmq, "host", "jd-host")
    monkeypatch.setitem(manager.app.conf, "broker_url", MANAGER_BROKER)


def _send_records_broker(monkeypatch, task, result):
    """Replace task.delay with one that records the broker the app would have sent the task to."""
    sent = []

    def _delay(*args, **kwargs):
        sent.append({"broker_url": manager.app.conf.broker_url, "args": args, "kwargs": kwargs})
        return SimpleNamespace(get=lambda timeout: result)

    monkeypatch.setattr(task, "delay", _delay)
    return sent


@pytest.mark.unit
def test_deobfuscate_file_is_sent_to_the_managers_broker(divergent_rabbitmq_config, monkeypatch, tmp_path):
    shared_input = tmp_path / "shared-input"
    monkeypatch.setattr(saq.js_deobfuscator, "SHARED_INPUT_DIR", str(shared_input))
    result_dir = tmp_path / "result"
    result_dir.mkdir()
    (result_dir / "deobfuscated.js").write_text("trace")
    sample = tmp_path / "sample.js"
    sample.write_text("eval('x')")
    sent = _send_records_broker(monkeypatch, manager.deobfuscate, str(result_dir))

    results = deobfuscate_file(str(sample), str(tmp_path / "collected"), timeout=9, scanner_timeout=4)

    assert [s["broker_url"] for s in sent] == [MANAGER_BROKER]
    (shared_path,) = sent[0]["args"]
    assert shared_path.startswith(str(shared_input)) and os.path.basename(shared_path) == "sample.js"
    assert sent[0]["kwargs"] == {"timeout": 4}
    assert results == [str(tmp_path / "collected" / "deobfuscated.js")]


@pytest.mark.unit
def test_maintain_files_is_sent_to_the_managers_broker(divergent_rabbitmq_config, monkeypatch):
    sent = _send_records_broker(monkeypatch, manager.maintain_files, {})

    maintain_files(3)

    assert [s["broker_url"] for s in sent] == [MANAGER_BROKER]


@pytest.fixture
def data_dirs(tmp_path, monkeypatch):
    input_dir, output_dir = tmp_path / "input", tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    monkeypatch.setattr(manager, "JS_DEOBFUSCATOR_DATA_DIRS", (str(input_dir), str(output_dir)))
    return input_dir, output_dir


def _job_dir(parent, name, age_days):
    path = parent / name
    path.mkdir()
    (path / "deobfuscated.js").write_text("x")
    then = time.time() - age_days * DAY
    os.utime(path, (then, then))
    return path


@pytest.mark.unit
def test_maintain_files_removes_job_directories_past_the_age(data_dirs):
    input_dir, output_dir = data_dirs
    old_input = _job_dir(input_dir, "old", 4)
    new_input = _job_dir(input_dir, "new", 1)
    old_output = _job_dir(output_dir, "old", 5)
    # only job directories are aged out
    stray = input_dir / "stray.js"
    stray.write_text("x")
    os.utime(stray, (time.time() - 10 * DAY,) * 2)

    deleted = manager.maintain_files(3)

    assert deleted == {str(input_dir): [str(old_input)], str(output_dir): [str(old_output)]}
    assert not old_input.exists() and not old_output.exists()
    assert new_input.exists() and stray.exists()


@pytest.mark.unit
def test_maintain_files_skips_a_missing_directory(data_dirs, tmp_path, monkeypatch):
    input_dir, _ = data_dirs
    old_input = _job_dir(input_dir, "old", 4)
    missing = tmp_path / "missing"
    monkeypatch.setattr(manager, "JS_DEOBFUSCATOR_DATA_DIRS", (str(missing), str(input_dir)))

    assert manager.maintain_files(3) == {str(missing): [], str(input_dir): [str(old_input)]}


@pytest.mark.unit
def test_maintain_files_keeps_going_past_a_directory_it_cannot_remove(data_dirs, monkeypatch, caplog):
    input_dir, _ = data_dirs
    stuck = _job_dir(input_dir, "a-stuck", 4)
    removable = _job_dir(input_dir, "b-removable", 4)
    real_rmtree = manager.shutil.rmtree

    def _rmtree(path, *args, **kwargs):
        if path == str(stuck):
            raise PermissionError("denied")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(manager.shutil, "rmtree", _rmtree)

    with caplog.at_level(logging.WARNING):
        deleted = manager.maintain_files(3)

    assert deleted[str(input_dir)] == [str(removable)]
    assert stuck.exists()
    assert any(str(stuck) in r.getMessage() and "denied" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_client_runs_the_task_and_waits_for_it(monkeypatch):
    calls = []

    def _delay(days):
        calls.append(days)
        return SimpleNamespace(get=lambda timeout: {"days": days, "timeout": timeout})

    monkeypatch.setattr(manager.maintain_files, "delay", _delay)

    assert maintain_files(7, timeout=12) == {"days": 7, "timeout": 12}
    assert calls == [7]


@pytest.mark.unit
@pytest.mark.parametrize("argv, expected_days", [
    ([], None),
    (["--max-file-age-days", "5"], 5),
])
def test_cli_maintain_files(monkeypatch, capsys, argv, expected_days):
    if expected_days is None:
        expected_days = get_config().js_deobfuscator.max_file_age_days
    monkeypatch.setattr(js_deobfuscator_cli, "maintain_files", lambda days: {"days": days})

    args = get_cli_parser().parse_args(["js-deobfuscator", "maintain-files", *argv])

    assert args.func(args) == os.EX_OK
    assert capsys.readouterr().out == f"{{'days': {expected_days}}}\n"
