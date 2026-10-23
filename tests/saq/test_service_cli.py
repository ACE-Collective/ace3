"""Tests for `ace service start`: the lifecycle that every service container runs.

Each case runs in a subprocess, because start_service installs signal handlers and ends in
os._exit(), and a regression here is a hang, which in-process would wedge the suite."""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

_PROGRAM = """
import logging, os, signal, sys, threading, time
from argparse import Namespace
from types import SimpleNamespace
sys.path.insert(0, {repo!r})
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="LOG %(levelname)s %(message)s")

import saq.cli.commands.service as service_cli
import saq.configuration.config
import saq.service

BEHAVIOR = {behavior!r}

def say(event):
    print(event, flush=True)

class FakeService:
    def __init__(self):
        self.stopped = threading.Event()

    def start(self):
        say("start")
        if BEHAVIOR == "start_raises":
            raise RuntimeError("start blew up")

    def start_single_threaded(self):
        say("start_single_threaded")

    def wait(self):
        say("wait")
        if BEHAVIOR == "wait_raises":
            raise RuntimeError("wait blew up")
        if BEHAVIOR in ("threaded", "stop_wedges", "wait_raises_when_stopped"):
            # a threaded service waits until it is stopped (bounded so a failure cannot hang)
            self.stopped.wait(20)
            if BEHAVIOR == "wait_raises_when_stopped":
                raise RuntimeError("wait blew up on the way out")

    def stop(self):
        say("stop")
        if BEHAVIOR == "stop_wedges":
            time.sleep(60)
        self.stopped.set()

saq.service.load_service_by_name = lambda name: FakeService()
saq.configuration.config.get_service_config = lambda name: SimpleNamespace(shutdown_deadline_seconds=3)

if BEHAVIOR in ("threaded", "stop_wedges", "wait_raises_when_stopped"):
    def _sigterm():
        time.sleep(0.5)
        say("sigterm")
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=_sigterm, daemon=True).start()

service_cli.start_service(Namespace(service="fake", single_threaded=BEHAVIOR == "single_threaded"))
say("RETURNED")
"""


def _run(tmp_path, behavior: str) -> subprocess.CompletedProcess:
    program = tmp_path / "service_start.py"
    program.write_text(_PROGRAM.format(repo=str(REPO_ROOT), behavior=behavior))
    return subprocess.run([sys.executable, str(program)], capture_output=True, text=True, timeout=30)


EVENTS = {"start", "start_single_threaded", "wait", "stop", "sigterm", "RETURNED"}


def _events(result: subprocess.CompletedProcess) -> list[str]:
    """What the fake service printed, without the log records and tracebacks around it."""
    return [line for line in result.stdout.splitlines() if line in EVENTS]


@pytest.mark.unit
def test_a_blocking_service_that_finishes_is_stopped_and_exits_0(tmp_path):
    result = _run(tmp_path, "blocking")

    assert result.returncode == 0, result.stderr[-2000:]
    # wait() runs twice: once watching for the service to finish, once while shutting down
    assert _events(result) == ["start", "wait", "stop", "wait"]
    assert "LOG INFO service fake finished on its own" in result.stdout
    assert "LOG INFO service fake exited with code 0" in result.stdout


@pytest.mark.unit
def test_single_threaded(tmp_path):
    result = _run(tmp_path, "single_threaded")

    assert result.returncode == 0, result.stderr[-2000:]
    assert _events(result)[0] == "start_single_threaded"


@pytest.mark.unit
def test_sigterm_stops_a_threaded_service(tmp_path):
    result = _run(tmp_path, "threaded")

    assert result.returncode == 0, result.stderr[-2000:]
    events = _events(result)
    assert events[:3] == ["start", "wait", "sigterm"]
    assert "stop" in events[3:]
    assert "RETURNED" not in events
    assert "finished on its own" not in result.stdout


@pytest.mark.unit
def test_a_service_that_fails_to_start_is_stopped_and_exits_1(tmp_path):
    result = _run(tmp_path, "start_raises")

    assert result.returncode == 1, result.stderr[-2000:]
    assert _events(result) == ["start", "stop", "wait"]
    assert "LOG ERROR error starting service fake: start blew up" in result.stdout
    assert "LOG INFO service fake exited with code 1" in result.stdout


@pytest.mark.unit
def test_a_failing_wait_is_an_error_and_exits_1(tmp_path):
    """A service whose wait() raises fell over: it used to be logged at WARNING, without a
    traceback or an error report, and exit 0 as if it had finished cleanly."""
    result = _run(tmp_path, "wait_raises")

    assert result.returncode == 1, result.stderr[-2000:]
    assert "LOG ERROR error waiting for service fake: wait blew up" in result.stdout
    assert "Traceback (most recent call last):" in result.stdout
    assert "finished on its own" not in result.stdout
    assert "LOG INFO service fake exited with code 1" in result.stdout


@pytest.mark.unit
def test_a_wait_that_fails_during_shutdown_is_not_an_error(tmp_path):
    result = _run(tmp_path, "wait_raises_when_stopped")

    # the bounded wait() of the shutdown logs it; the watching thread may not get to before the exit
    assert result.returncode == 0, result.stderr[-2000:]
    assert "wait blew up on the way out" in result.stdout
    assert "LOG ERROR" not in result.stdout


@pytest.mark.unit
def test_a_wedged_stop_still_exits_within_the_deadline(tmp_path):
    result = _run(tmp_path, "stop_wedges")

    # stop() sleeps for 60 seconds; the process exits on the 3 second deadline regardless
    assert result.returncode == 0, result.stderr[-2000:]
    assert "stop" in _events(result)
    assert "LOG INFO service fake exited with code 0" in result.stdout
