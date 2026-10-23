"""Every forked worker leads a process group, and the manager kills that group whenever the worker ends."""

import logging
import os
import select
import signal
import subprocess
import sys
import time
from unittest.mock import Mock

import psutil
import pytest

from saq.engine import worker as worker_module
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode, EngineType, WorkerStatus
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker, _process_group_members
from saq.engine.worker_manager import WorkerManager
from saq.environment import ACE_MP_CONTEXT
from saq.shutdown import reset_shutdown_coordinator
from tests.saq.helpers import wait_for_condition


def _configuration_manager() -> ConfigurationManager:
    return ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=True))


def _is_running(pid: int) -> bool:
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def _read_pids(read_fd: int) -> list[int]:
    """The pids a stub worker_loop wrote to the pipe, waiting at most 10 seconds for them."""
    ready, _, _ = select.select([read_fd], [], [], 10)
    assert ready, "the worker never reported"
    return [int(pid) for pid in os.read(read_fd, 1024).split()]


def _killed_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage().startswith("killed ")]


@pytest.fixture
def pipe():
    read_fd, write_fd = os.pipe()
    yield read_fd, write_fd
    for fd in (read_fd, write_fd):
        try:
            os.close(fd)
        except OSError:
            pass


@pytest.fixture
def started():
    """Workers and processes a test started, killed afterwards whatever happened to the test."""
    workers, pids = [], []
    yield workers, pids
    for worker in workers:
        if worker.process is not None and worker.process.pid is not None:
            try:
                os.killpg(worker.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            worker.process.join(5)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _start_worker(started, worker_loop) -> Worker:
    """A real Worker, forked by its real start(), that runs worker_loop in place of the engine's."""
    worker = Worker(name="test_worker", configuration_manager=_configuration_manager(),
                    node_manager=Mock(spec=NodeManagerInterface))
    worker.worker_loop = worker_loop
    started[0].append(worker)
    worker.start()
    return worker


def _start_a_child_then(write_fd: int, then):
    """A worker_loop that starts a child, reports its pid and then does what then says."""
    def worker_loop(execution_mode, pending_failure):
        child = subprocess.Popen(["sleep", "60"])
        os.write(write_fd, f"{child.pid} ".encode())
        then()

    return worker_loop


def _manager() -> WorkerManager:
    return WorkerManager(_configuration_manager(), Mock(spec=NodeManagerInterface))


def _leave_children_and_die(write_fd: int):
    """A worker_loop that does what the incident's worker did: its module started a process, and a copy of
    the worker that never reached its exec, then the analysis module monitor ended it with os._exit(1)."""
    def worker_loop(execution_mode, pending_failure):
        child = subprocess.Popen(["sleep", "60"])
        copy = os.fork()
        if copy == 0:
            time.sleep(60)
            os._exit(0)

        os.write(write_fd, f"{child.pid} {copy} ".encode())
        os._exit(1)

    return worker_loop


@pytest.mark.unit
def test_start_makes_the_worker_lead_a_group_from_the_manager_side(monkeypatch, started):
    # setpgid does nothing in the worker, so only the call start() makes is left
    real_setpgid, manager_pid = os.setpgid, os.getpid()
    monkeypatch.setattr(os, "setpgid", lambda pid, pgrp: real_setpgid(pid, pgrp) if os.getpid() == manager_pid else None)

    worker = _start_worker(started, lambda execution_mode, pending_failure: time.sleep(60))

    assert os.getpgid(worker.process.pid) == worker.process.pid != os.getpgrp()


@pytest.mark.unit
def test_the_worker_leads_its_group_from_its_own_side(monkeypatch, started, pipe):
    # setpgid does nothing in the manager, so only the call the worker makes is left
    read_fd, write_fd = pipe
    real_setpgid, manager_pid = os.setpgid, os.getpid()
    monkeypatch.setattr(os, "setpgid", lambda pid, pgrp: real_setpgid(pid, pgrp) if os.getpid() != manager_pid else None)

    def worker_loop(execution_mode, pending_failure):
        os.write(write_fd, f"{os.getpgrp()} ".encode())
        time.sleep(60)

    worker = _start_worker(started, worker_loop)

    assert _read_pids(read_fd) == [worker.process.pid]


@pytest.mark.unit
def test_check_kills_what_a_dead_worker_left_running(started, pipe, caplog):
    read_fd, write_fd = pipe
    worker = _start_worker(started, _leave_children_and_die(write_fd))
    left = _read_pids(read_fd)
    started[1].extend(left)

    # not join(): the copy holds the write end of the process's sentinel, so join() waits out its timeout
    wait_for_condition(lambda: worker.process.exitcode is not None, timeout=10)
    assert worker.process.exitcode == 1
    assert all(_is_running(pid) for pid in left)

    with caplog.at_level(logging.WARNING):
        assert _manager().check(worker) == WorkerStatus.DEAD

    wait_for_condition(lambda: not any(_is_running(pid) for pid in left), timeout=10)
    [record] = _killed_records(caplog)
    assert record.levelno == logging.WARNING
    assert sorted(record.killed_pids) == sorted(left)
    assert record.exit_code == 1
    assert record.worker == "test_worker"


@pytest.mark.unit
@pytest.mark.parametrize("limit", ["timeout", "memory"])
def test_check_kills_the_worker_and_everything_it_started(started, pipe, caplog, limit):
    read_fd, write_fd = pipe
    worker = _start_worker(started, _start_a_child_then(write_fd, lambda: time.sleep(60)))
    [child] = _read_pids(read_fd)
    started[1].append(child)

    manager = _manager()
    if limit == "timeout":
        worker.analysis_has_timed_out = lambda record: True
    else:
        manager.config.memory_limit_kill = 0

    with caplog.at_level(logging.WARNING):
        assert manager.check(worker) == WorkerStatus.DEAD

    assert worker.process.exitcode == -signal.SIGKILL
    wait_for_condition(lambda: not _is_running(child), timeout=10)
    [record] = _killed_records(caplog)
    assert record.killed_pids == [child]


@pytest.mark.unit
def test_check_logs_nothing_after_a_clean_exit(started, caplog):
    worker = _start_worker(started, lambda execution_mode, pending_failure: None)
    worker.process.join(10)
    assert worker.process.exitcode == 0

    with caplog.at_level(logging.WARNING):
        assert _manager().check(worker) == WorkerStatus.DEAD

    # an empty group is the normal case (every worker refresh), not an error
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.fixture
def shutdown_coordinator():
    reset_shutdown_coordinator()
    yield
    reset_shutdown_coordinator()


@pytest.mark.unit
def test_shutdown_kills_what_a_worker_that_exited_during_it_left_running(started, pipe, caplog, shutdown_coordinator):
    # supervise_shutdown's is_alive() reaps a worker that exits while it waits, so check() never sees it die
    read_fd, write_fd = pipe
    worker = _start_worker(started, _leave_children_and_die(write_fd))
    left = _read_pids(read_fd)
    started[1].extend(left)
    wait_for_condition(lambda: not worker.is_alive(), timeout=10)

    manager = _manager()
    manager.workers = [worker]
    with caplog.at_level(logging.WARNING):
        manager.supervise_shutdown(poll_interval=0.05)

    wait_for_condition(lambda: not any(_is_running(pid) for pid in left), timeout=10)
    [record] = _killed_records(caplog)
    assert sorted(record.killed_pids) == sorted(left)


@pytest.mark.unit
def test_shutdown_finishes_with_a_worker_whose_start_failed(shutdown_coordinator, caplog):
    # restart_worker adds the replacement before it starts it, so a fork that fails leaves one that never ran
    worker = Worker(name="test_worker", configuration_manager=_configuration_manager(),
                    node_manager=Mock(spec=NodeManagerInterface))
    worker.process = ACE_MP_CONTEXT.Process(target=lambda: None)

    manager = _manager()
    manager.workers = [worker]
    with caplog.at_level(logging.INFO):
        manager.supervise_shutdown(poll_interval=0.05)

    assert "all workers shut down" in caplog.text


@pytest.mark.unit
def test_kill_without_a_process_does_nothing():
    worker = Worker(name="test_worker", configuration_manager=_configuration_manager(),
                    node_manager=Mock(spec=NodeManagerInterface))
    assert worker.process is None
    worker.kill()


@pytest.mark.unit
def test_wait_for_start_kills_the_group_of_a_worker_that_does_not_start(started, pipe):
    read_fd, write_fd = pipe
    worker = _start_worker(started, _start_a_child_then(write_fd, lambda: time.sleep(60)))
    [child] = _read_pids(read_fd)
    started[1].append(child)

    # it reports a start on the second wait, so the loop ends after one kill rather than 30 seconds later
    worker._worker_startup_event = Mock(wait=Mock(side_effect=[False, True]))
    worker.wait_for_start()

    assert worker.process.exitcode == -signal.SIGKILL
    wait_for_condition(lambda: not _is_running(child), timeout=10)


@pytest.mark.unit
def test_kill_logs_a_group_it_cannot_signal(monkeypatch, caplog):
    worker = Worker(name="test_worker", configuration_manager=_configuration_manager(),
                    node_manager=Mock(spec=NodeManagerInterface))
    worker.process = Mock(pid=2 ** 22 + 1)

    def killpg(pgid, sig):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "killpg", killpg)
    worker.kill()

    [record] = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert "unable to kill the process group of worker test_worker" in record.getMessage()
    assert record.exc_info
    worker.process.join.assert_not_called()


@pytest.mark.unit
def test_kill_still_kills_a_group_it_cannot_list(monkeypatch, started, pipe, caplog):
    read_fd, write_fd = pipe
    worker = _start_worker(started, _start_a_child_then(write_fd, lambda: time.sleep(60)))
    [child] = _read_pids(read_fd)
    started[1].append(child)

    def broken(pgid):
        raise RuntimeError("no /proc")

    monkeypatch.setattr(worker_module, "_process_group_members", broken)
    worker.kill()

    assert worker.process.exitcode == -signal.SIGKILL
    wait_for_condition(lambda: not _is_running(child), timeout=10)
    [record] = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert "unable to list the process group of worker test_worker" in record.getMessage()
    assert record.exc_info


@pytest.mark.unit
def test_process_group_members_are_the_live_processes_besides_the_leader(monkeypatch, started):
    # a leader with two children in its group: one still running and one that has exited, unreaped
    leader = subprocess.Popen(
        [sys.executable, "-c",
         "import os, subprocess, sys, time\n"
         "running = subprocess.Popen(['sleep', '60'])\n"
         "exited = subprocess.Popen(['true'])\n"
         "print(running.pid, exited.pid, flush=True)\n"
         "time.sleep(60)\n"],
        stdout=subprocess.PIPE, process_group=0)
    started[1].append(leader.pid)
    running, exited = (int(pid) for pid in leader.stdout.readline().split())
    started[1].append(running)
    wait_for_condition(lambda: psutil.Process(exited).status() == psutil.STATUS_ZOMBIE, timeout=10)

    assert _process_group_members(leader.pid) == [(running, f"{running} sleep")]

    # a process that exits while the group is being listed is left out
    real_getpgid = os.getpgid

    def getpgid(pid):
        if pid == running:
            raise ProcessLookupError(pid)
        return real_getpgid(pid)

    monkeypatch.setattr(os, "getpgid", getpgid)
    assert _process_group_members(leader.pid) == []

    os.killpg(leader.pid, signal.SIGKILL)
    leader.wait(10)


@pytest.mark.integration
def test_single_threaded_mode_keeps_the_callers_process_group(root_analysis, monkeypatch):
    # the worker loop runs in this process, which must stay in its caller's group (a shell's job, a test run)
    calls = []
    monkeypatch.setattr(os, "setpgid", lambda *args: calls.append(args))
    process_group = os.getpgrp()

    root_analysis.analysis_mode = "test_groups"
    root_analysis.save()
    root_analysis.schedule()
    Engine().start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert calls == []
    assert os.getpgrp() == process_group
