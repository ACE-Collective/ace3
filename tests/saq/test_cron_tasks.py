"""Tests for saq.cron_tasks, the run-parts style runner behind bin/{hourly,daily,weekly}-maintenance.sh."""

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

import saq.cron_tasks
from saq.cli.commands.cron import CRON_CADENCE_CHOICES
from saq.cron import ACECronConfig
from saq.cron_tasks import CRON_CADENCES, CronTask, CronTaskRunner, discover_tasks, get_max_parallel_tasks, run_tasks
from tests import unittest_session

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_task(path: Path, body: str = "exit 0", executable: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n" + body + "\n")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _cron_config(max_parallel_tasks=None) -> ACECronConfig:
    return ACECronConfig(
        name="cron",
        description="cron service",
        enabled=True,
        python_module="saq.cron",
        python_class="ACECronService",
        cron_config_path="etc/cron.yaml",
        max_parallel_tasks=max_parallel_tasks,
    )


@pytest.fixture
def exec_tmp():
    """a temp dir the tasks can be executed from

    pytest's tmp_path lives under /tmp, which is mounted noexec in the container, so the
    scripts go under this slot's own data directory instead
    """
    os.makedirs(unittest_session.get_session_data_dir(), exist_ok=True)
    path = tempfile.mkdtemp(prefix="cron-tasks-", dir=unittest_session.get_session_data_dir())
    yield Path(path)
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def saq_home(exec_tmp, monkeypatch):
    """a temp SAQ_HOME with a stub bin/run-cron-job and no integrations"""
    home = exec_tmp / "home"
    # the stub drops the slug and runs the task, like the real wrapper minus the logging
    _write_task(home / "bin" / "run-cron-job", 'shift\nexec "$@"')
    monkeypatch.setattr(saq.cron_tasks, "get_base_dir", lambda: str(home))
    monkeypatch.setattr(saq.cron_tasks, "get_valid_integration_dirs", lambda: [])
    monkeypatch.setattr(saq.cron_tasks, "get_service_config", lambda name: _cron_config())
    return home


@pytest.fixture
def integrations(exec_tmp, monkeypatch):
    """creates integration dirs; returns a function (name, enabled) -> integration dir"""
    dirs = []
    disabled = set()
    monkeypatch.setattr(saq.cron_tasks, "get_valid_integration_dirs", lambda: [str(d) for d in dirs])
    monkeypatch.setattr(saq.cron_tasks, "is_integration_enabled", lambda name: name not in disabled)

    def _create(name: str, enabled: bool = True) -> Path:
        path = exec_tmp / "integrations" / name
        path.mkdir(parents=True)
        dirs.append(path)
        if not enabled:
            disabled.add(name)
        return path

    return _create


@pytest.mark.unit
class TestDiscoverTasks:
    def test_finds_executables_in_order(self, saq_home):
        _write_task(saq_home / "etc/cron/daily/zeta")
        _write_task(saq_home / "etc/cron/daily/alpha")

        tasks = discover_tasks("daily")

        assert [t.name for t in tasks] == ["alpha", "zeta"]
        assert tasks[0] == CronTask(
            name="alpha",
            path=str(saq_home / "etc/cron/daily/alpha"),
            source="core",
            slug="daily-alpha",
        )

    def test_skips_files_that_are_not_tasks(self, saq_home):
        cron_dir = saq_home / "etc/cron/daily"
        _write_task(cron_dir / "real")
        _write_task(cron_dir / "not-executable", executable=False)
        _write_task(cron_dir / ".hidden")
        for suffix in ("~", ".bak", ".orig", ".disabled", ".md"):
            _write_task(cron_dir / f"real{suffix}")
        (cron_dir / "subdir").mkdir()

        assert [t.name for t in discover_tasks("daily")] == ["real"]

    def test_cadences_are_separate(self, saq_home):
        _write_task(saq_home / "etc/cron/hourly/h")
        _write_task(saq_home / "etc/cron/weekly/w")

        assert [t.name for t in discover_tasks("hourly")] == ["h"]
        assert [t.name for t in discover_tasks("weekly")] == ["w"]
        assert discover_tasks("daily") == []

    def test_invalid_cadence(self, saq_home):
        with pytest.raises(ValueError):
            discover_tasks("monthly")

    def test_includes_enabled_integrations(self, saq_home, integrations):
        _write_task(saq_home / "etc/cron/daily/core-task")
        zed = integrations("zed")
        _write_task(zed / "etc/cron/daily/cleanup")
        abc = integrations("abc")
        _write_task(abc / "etc/cron/daily/cleanup")
        _write_task(abc / "etc/cron/hourly/other")
        off = integrations("off", enabled=False)
        _write_task(off / "etc/cron/daily/cleanup")
        # an integration with no cron directory at all is fine
        integrations("nothing")

        tasks = discover_tasks("daily")

        assert [(t.source, t.slug) for t in tasks] == [
            ("core", "daily-core-task"),
            ("abc", "daily-abc-cleanup"),
            ("zed", "daily-zed-cleanup"),
        ]
        assert tasks[1].path == str(abc / "etc/cron/daily/cleanup")


@pytest.mark.unit
class TestMaxParallelTasks:
    def test_argument_wins(self, saq_home, monkeypatch):
        monkeypatch.setattr(saq.cron_tasks, "get_service_config", lambda name: _cron_config(3))
        assert get_max_parallel_tasks(7) == 7

    def test_configured_value(self, saq_home, monkeypatch):
        monkeypatch.setattr(saq.cron_tasks, "get_service_config", lambda name: _cron_config(3))
        assert get_max_parallel_tasks() == 3

    def test_defaults_to_cpu_count(self, saq_home, monkeypatch):
        monkeypatch.setattr(saq.cron_tasks.os, "cpu_count", lambda: 5)
        assert get_max_parallel_tasks() == 5


@pytest.mark.unit
class TestRunTasks:
    def test_all_succeed(self, saq_home, tmp_path):
        for name in ("a", "b", "c"):
            _write_task(saq_home / f"etc/cron/daily/{name}", f"touch {tmp_path}/ran-{name}")

        assert run_tasks("daily") == 0
        assert sorted(p.name for p in tmp_path.glob("ran-*")) == ["ran-a", "ran-b", "ran-c"]

    def test_failure_does_not_stop_the_others(self, saq_home, tmp_path):
        _write_task(saq_home / "etc/cron/daily/bad", "exit 3")
        _write_task(saq_home / "etc/cron/daily/good", f"touch {tmp_path}/ran-good")

        assert run_tasks("daily", max_parallel=1) == 1
        assert (tmp_path / "ran-good").exists()

    def test_no_tasks(self, saq_home):
        assert run_tasks("weekly") == 0

    def test_runs_in_parallel_up_to_the_limit(self, saq_home, tmp_path):
        running = tmp_path / "running"
        running.mkdir()
        peaks = tmp_path / "peaks"
        # each task marks itself running, records how many are running, then holds for a bit
        body = (
            f'mkdir "{running}/$(basename "$0")"\n'
            f'ls "{running}" | wc -l >> "{peaks}"\n'
            "sleep 0.5\n"
            f'rmdir "{running}/$(basename "$0")"'
        )
        for index in range(6):
            _write_task(saq_home / f"etc/cron/daily/task{index}", body)

        assert run_tasks("daily", max_parallel=2) == 0

        counts = [int(line) for line in peaks.read_text().split()]
        assert len(counts) == 6
        assert max(counts) == 2

    def test_passes_slug_and_path_to_run_cron_job(self, saq_home, tmp_path):
        record = tmp_path / "args"
        _write_task(saq_home / "bin" / "run-cron-job", f'echo "$@" > "{record}"')
        task = _write_task(saq_home / "etc/cron/hourly/thing")

        assert run_tasks("hourly") == 0
        assert record.read_text().split() == ["hourly-thing", str(task)]


    def test_unlaunchable_wrapper_is_a_task_failure(self, saq_home, tmp_path):
        (saq_home / "bin" / "run-cron-job").unlink()
        _write_task(saq_home / "etc/cron/daily/a")
        _write_task(saq_home / "etc/cron/daily/b")

        results = CronTaskRunner(discover_tasks("daily"), max_parallel=2).run()

        assert sorted(r.exit_code for r in results) == [127, 127]
        assert run_tasks("daily") == 1

    def test_nothing_starts_after_shutdown(self, saq_home, tmp_path):
        _write_task(saq_home / "etc/cron/daily/a", f"touch {tmp_path}/ran-a")
        runner = CronTaskRunner(discover_tasks("daily"), max_parallel=1)
        runner.request_shutdown()

        results = runner.run()

        assert [r.skipped for r in results] == [True]
        assert not (tmp_path / "ran-a").exists()


@pytest.mark.unit
class TestShippedCronTasks:
    """guards etc/cron itself"""

    def test_cli_cadences_match(self):
        assert tuple(CRON_CADENCE_CHOICES) == CRON_CADENCES

    @pytest.mark.parametrize("cadence", CRON_CADENCES)
    def test_every_cadence_has_executable_tasks(self, cadence):
        cron_dir = REPO_ROOT / "etc" / "cron" / cadence
        assert cron_dir.is_dir()

        entries = list(cron_dir.iterdir())
        assert entries
        for entry in entries:
            # a task committed without its executable bit would be silently skipped
            assert entry.is_file() and os.access(entry, os.X_OK), f"{entry} is not an executable task"

    def test_no_task_is_git_ignored(self):
        """a task caught by a .gitignore pattern exists locally but never ships

        (the repo-wide "logs" pattern once swallowed a task named etc/cron/daily/logs)
        """
        if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
            pytest.skip("not a git checkout")

        tasks = [str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "etc" / "cron").glob("*/*")]
        result = subprocess.run(["git", "check-ignore", *tasks], cwd=REPO_ROOT, capture_output=True, text=True)
        assert result.stdout.split() == []
