"""The sandbox as any caller uses it, with its own config and working directory root."""

import datetime
import logging
import os
import threading
import time
import uuid

import pytest

from saq.configuration.schema import SandboxConfig
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.sandbox import runner
from saq.sandbox.launcher import NET_ABI, landlock_abi
from saq.sandbox.runner import (
    SandboxCancelled,
    build_sandbox_argv,
    create_workdir,
    landlock_available,
    run_sandboxed,
    sandbox_python,
    sweep_stale_workdirs,
)

PYTHON = sandbox_python()

# the tests that are not about TCP leave it unrestricted, so they run on any kernel with Landlock and
# not only on one with TCP port rules (ABI 4, Linux 6.7)
NO_TCP_RULES = SandboxConfig(allowed_tcp_ports=None)


def _run_python(code: str, workdir: str, *args: str, config: SandboxConfig = NO_TCP_RULES):
    argv = build_sandbox_argv([PYTHON, "-I", "-c", code, *args], workdir, config, datetime.timedelta(seconds=30))
    return run_sandboxed(argv, None, {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir}, workdir, datetime.timedelta(seconds=30), 1024 * 1024)


@pytest.mark.unit
def test_default_config_allows_no_tcp():
    # a caller that does not name ports gets none; the hunt config is the one that opens 443 and 53
    assert SandboxConfig().allowed_tcp_ports == []
    argv = build_sandbox_argv(["/bin/true"], "/nonexistent", SandboxConfig(), datetime.timedelta(seconds=5))
    assert "--tcp-ports=" in argv[:argv.index("--")]


@pytest.mark.unit
@pytest.mark.parametrize("cpu_seconds,expected", [(None, "--cpu=5"), (60, "--cpu=60")])
def test_cpu_time_is_the_timeout_unless_given(cpu_seconds, expected):
    argv = build_sandbox_argv(["/bin/true"], "/nonexistent", SandboxConfig(), datetime.timedelta(seconds=4.5),
                              cpu_seconds=cpu_seconds)
    assert expected in argv


@pytest.mark.unit
def test_workdir_is_created_under_the_callers_root(tmp_path):
    root = str(tmp_path / "svs")
    with create_workdir(root) as workdir:
        assert os.path.dirname(workdir) == root
        assert os.path.isdir(workdir)

    assert not os.path.exists(workdir)


@pytest.mark.unit
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_command_writes_its_workdir_and_cannot_read_saq_home(tmp_path):
    code = (
        "import os, sys\n"
        "open('out.txt', 'w').write('ok')\n"
        "try:\n"
        "    os.listdir(sys.argv[1])\n"
        "    print('read')\n"
        "except PermissionError:\n"
        "    print('refused')"
    )
    with create_workdir(str(tmp_path)) as workdir:
        result = _run_python(code, workdir, get_base_dir())
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "refused"
        with open(os.path.join(workdir, "out.txt")) as fp:
            assert fp.read() == "ok"


@pytest.mark.unit
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_extra_paths_are_readable_or_writable_as_named(tmp_path):
    # what an analysis module's tool gets: the file it analyzes, a directory of its program's and
    # the directory it extracts into. tmp_path, not a sandbox root: its siblings stay unreadable
    readable_file = tmp_path / "sample.bin"
    readable_file.write_text("sample")
    (tmp_path / "beside.bin").write_text("beside")
    readable_dir = tmp_path / "program"
    readable_dir.mkdir()
    (readable_dir / "data").write_text("data")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    code = (
        "import sys\n"
        "def attempt(f):\n"
        "    try:\n"
        "        f()\n"
        "        return 'yes'\n"
        "    except PermissionError:\n"
        "        return 'no'\n"
        "print(attempt(lambda: open(sys.argv[1]).read()),\n"
        "      attempt(lambda: open(sys.argv[4]).read()),\n"
        "      attempt(lambda: open(sys.argv[2] + '/data').read()),\n"
        "      attempt(lambda: open(sys.argv[2] + '/new', 'w')),\n"
        "      attempt(lambda: open(sys.argv[3] + '/new', 'w').write('x')))"
    )
    with create_workdir(str(tmp_path / "root")) as workdir:
        argv = build_sandbox_argv([PYTHON, "-I", "-c", code, str(readable_file), str(readable_dir), str(output_dir),
                                   str(tmp_path / "beside.bin")],
                                  workdir, NO_TCP_RULES, datetime.timedelta(seconds=30), read_files=[str(readable_file)],
                                  read_dirs=[str(readable_dir)], write_dirs=[str(output_dir)])
        result = run_sandboxed(argv, None, {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir}, workdir,
                               datetime.timedelta(seconds=30), 1024 * 1024)

    assert result.stdout.split() == ["yes", "no", "yes", "no", "yes"], result.stderr
    assert (output_dir / "new").read_text() == "x"


@pytest.mark.unit
@pytest.mark.skipif(landlock_abi() < NET_ABI, reason=f"TCP port rules need Landlock ABI {NET_ABI} (Linux 6.7)")
def test_default_config_refuses_every_tcp_connection(tmp_path):
    code = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('127.0.0.1', 443), timeout=5)\n"
        "    print('connected')\n"
        "except PermissionError:\n"
        "    print('refused')\n"
        "except OSError:\n"
        "    print('allowed')"
    )
    with create_workdir(str(tmp_path)) as workdir:
        result = _run_python(code, workdir, config=SandboxConfig())
        assert result.stdout.strip() == "refused", result.stderr


@pytest.mark.unit
def test_sweep_removes_only_stale_workdirs(tmp_path):
    # a temp directory, not a real sandbox root: those sit under data_unittest/, a bind mount in the
    # dev container, where a mode-000 directory cannot be chmodded from inside the container -- it
    # would outlive a failed sweep and break every later data directory reset
    root = str(tmp_path)
    stale = os.path.join(root, f"cmd-stale-{uuid.uuid4().hex}")
    fresh = os.path.join(root, f"cmd-fresh-{uuid.uuid4().hex}")
    os.makedirs(os.path.join(stale, "locked"))
    os.makedirs(fresh)
    # a command may leave a directory it made unwritable
    os.chmod(os.path.join(stale, "locked"), 0)
    old = (datetime.datetime.now() - datetime.timedelta(days=2)).timestamp()
    os.utime(stale, (old, old))

    sweep_stale_workdirs(root)

    assert not os.path.exists(stale)
    assert os.path.exists(fresh)


@pytest.mark.unit
def test_sweep_of_a_missing_root_is_a_no_op(tmp_path):
    sweep_stale_workdirs(str(tmp_path / "never-created"))


@pytest.mark.unit
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_cancel_stops_the_command_and_everything_it_started(tmp_path):
    # the command starts a child that outlives it in the background, then sleeps
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n"
        "open('child.pid', 'w').write(str(child.pid))\n"
        "time.sleep(60)"
    )
    cancel = threading.Event()
    with create_workdir(str(tmp_path)) as workdir:
        argv = build_sandbox_argv([PYTHON, "-I", "-c", code], workdir, NO_TCP_RULES, datetime.timedelta(seconds=60))
        env = {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir}
        pid_file = os.path.join(workdir, "child.pid")
        threading.Thread(target=lambda: (_wait_for(pid_file), cancel.set()), daemon=True).start()

        started = time.monotonic()
        with pytest.raises(SandboxCancelled):
            run_sandboxed(argv, None, env, workdir, datetime.timedelta(seconds=60), 1024 * 1024, cancel=cancel.is_set)

        assert time.monotonic() - started < 30
        with open(pid_file) as fp:
            child_pid = int(fp.read())

    assert not _alive(child_pid)


@pytest.mark.unit
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_a_cancel_that_stays_false_changes_nothing(tmp_path):
    with create_workdir(str(tmp_path)) as workdir:
        argv = build_sandbox_argv([PYTHON, "-I", "-c", "print('done')"], workdir, NO_TCP_RULES,
                                  datetime.timedelta(seconds=30))
        result = run_sandboxed(argv, None, {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir}, workdir,
                               datetime.timedelta(seconds=30), 1024 * 1024, cancel=threading.Event().is_set)

    assert (result.returncode, result.stdout.strip()) == (0, "done")


@pytest.mark.unit
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_an_analysis_module_cancel_stops_the_command(tmp_path, test_context):
    # what a module hands run_sandboxed, cancelled from another thread as the engine would
    module = AnalysisModule(context=test_context, config=AnalysisModuleConfig(
        name="test", python_module="saq.modules.base_module", python_class="AnalysisModule", enabled=True))
    with create_workdir(str(tmp_path)) as workdir:
        argv = build_sandbox_argv([PYTHON, "-I", "-c", "open('started', 'w'); import time; time.sleep(60)"],
                                  workdir, NO_TCP_RULES, datetime.timedelta(seconds=60))
        started_file = os.path.join(workdir, "started")
        threading.Thread(target=lambda: (_wait_for(started_file), module.cancel_analysis()), daemon=True).start()

        started = time.monotonic()
        with pytest.raises(SandboxCancelled):
            run_sandboxed(argv, None, {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir}, workdir,
                          datetime.timedelta(seconds=60), 1024 * 1024, cancel=module.should_stop)

        assert time.monotonic() - started < 30


def _wait_for(path: str, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while not os.path.exists(path) and time.monotonic() < deadline:
        time.sleep(0.1)


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fp:
            # a zombie is dead, it only waits for its parent to reap it
            return fp.read().split(")")[-1].split()[0] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.unit
def test_a_probe_that_could_not_run_is_tried_again(monkeypatch, caplog):
    # a fork that failed for want of a pid, under load: the next call asks the kernel again
    real_run = runner.subprocess.run
    calls = []

    def _run(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise BlockingIOError(11, "Resource temporarily unavailable")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(runner, "_LANDLOCK_AVAILABLE", None)
    monkeypatch.setattr(runner.subprocess, "run", _run)

    first = landlock_available()
    second = landlock_available()
    third = landlock_available()

    # no answer, which says nothing about the kernel
    assert first is None
    assert second == third
    # the kernel's answer is kept
    assert len(calls) == 2
    [record] = [r for r in caplog.records if "unable to probe for landlock support" in r.getMessage()]
    assert record.levelno == logging.ERROR
    assert record.exc_info


@pytest.mark.unit
@pytest.mark.parametrize("result,reason", [
    (runner.SandboxResult(2, "", "reading\nERROR: bad header\n\n"), "7z exited with status 2: ERROR: bad header"),
    (runner.SandboxResult(1, "", ""), "7z exited with status 1"),
    # the sandbox exits 128 + N for a command killed by signal N
    (runner.SandboxResult(128 + 9, "", ""), "7z was killed by signal 9"),
    (runner.SandboxResult(0, "", "x" * 600), f"7z exited with status 0: {'x' * 500}"),
], ids=["stderr", "silent", "signal", "long-line"])
def test_failure_reason(result, reason):
    assert result.failure_reason("7z") == reason
