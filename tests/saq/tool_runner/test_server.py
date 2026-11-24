"""The tool runner's server and client together, over a socket of their own."""

import datetime
import logging
import os
import shutil
import socket
import tempfile
import threading
import time

import pytest

from saq.configuration.schema import SandboxConfig
from saq.sandbox.runner import SandboxCancelled, SandboxOutputExceeded, sandbox_python
from saq.tool_runner import client as client_module, protocol, server as server_module
from saq.tool_runner.cgroup import RUN_PREFIX, CgroupUnavailable, RunCgroups
from saq.tool_runner.client import (
    ToolMemoryExceeded,
    ToolRunnerBusy,
    ToolRunnerFailed,
    ToolRunnerUnavailable,
    get_socket_path,
    run_on_runner,
)
from saq.tool_runner.server import STOP_SECONDS, ToolRunnerServer
from saq.yara_scanning.protocol import recv_json, send_json
from tests.saq.helpers import wait_for_condition

MIB = 1024 ** 2

# reserves 16 GiB of address space and touches none of it, as a GC or a thread arena does
_RESERVE = ("import mmap; m = mmap.mmap(-1, 16 * 1024 ** 3, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | "
            "mmap.MAP_NORESERVE); print('reserved')")


@pytest.fixture
def socket_dir():
    # a short path: a unix socket's is limited to 108 bytes
    path = tempfile.mkdtemp(prefix="tool-runner-", dir="/tmp")
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def start_server(socket_dir):
    servers = []

    def _start(**kwargs) -> ToolRunnerServer:
        server = ToolRunnerServer(os.path.join(socket_dir, f"{len(servers)}.sock"), io_timeout=5, **kwargs)
        server.start()
        servers.append(server)
        return server

    yield _start

    for server in servers:
        server.stop()
        server.wait_until_stopped()


def _python(server: ToolRunnerServer, code: str, workdir, *, timeout: float = 30, config: SandboxConfig | None = None,
            cancel=None, stdin_data: str | None = None):
    os.makedirs(workdir, exist_ok=True)
    return run_on_runner([sandbox_python(), "-I", "-c", code],
                         env={"PATH": "/usr/bin:/bin", "HOME": str(workdir), "TMPDIR": str(workdir)}, cwd=str(workdir),
                         workdir=str(workdir), timeout=datetime.timedelta(seconds=timeout),
                         config=config or SandboxConfig(memory_limit=256 * MIB), stdin_data=stdin_data, cancel=cancel,
                         socket_path=server.socket_path)


def _runs(server: ToolRunnerServer) -> list[str]:
    return [name for name in os.listdir(server.cgroups.parent) if name.startswith(f"{RUN_PREFIX}{os.getpid()}-")]


def _in_background(target) -> tuple[threading.Thread, dict]:
    outcome = {}

    def run():
        try:
            outcome["result"] = target()
        except BaseException as e:
            outcome["error"] = e

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, outcome


@pytest.mark.unit
def test_a_tool_runs_and_its_result_comes_back(start_server, tmp_path):
    server = start_server()

    result = _python(server, "import sys; print(sys.stdin.read().upper()); print('oops', file=sys.stderr); sys.exit(3)",
                     tmp_path / "work", stdin_data="given")

    assert result.returncode == 3
    assert result.stdout == "GIVEN\n"
    assert result.stderr == "oops\n"
    assert not result.output_exceeded


@pytest.mark.unit
def test_address_space_a_tool_reserves_is_not_its_memory(start_server, tmp_path):
    # the reservation is 64 times the limit; an RLIMIT_AS of the limit would refuse it
    server = start_server()

    result = _python(server, _RESERVE, tmp_path / "work")

    assert result.returncode == 0, result.stderr
    assert result.stdout == "reserved\n"


@pytest.mark.unit
def test_a_tool_that_uses_more_than_its_memory_limit_is_killed(start_server, tmp_path):
    server = start_server()

    with pytest.raises(ToolMemoryExceeded, match=f"more than its memory limit of {128 * MIB} bytes"):
        _python(server, "b = bytearray(512 * 1024 ** 2); print('survived')", tmp_path / "work",
                config=SandboxConfig(memory_limit=128 * MIB))

    assert _runs(server) == []


@pytest.mark.unit
def test_too_much_output_stops_the_tool_and_returns_what_it_wrote(start_server, tmp_path):
    server = start_server()

    with pytest.raises(SandboxOutputExceeded) as raised:
        _python(server, "import sys\nwhile True: sys.stdout.write('x' * 65536)", tmp_path / "work",
                config=SandboxConfig(memory_limit=256 * MIB, max_output_bytes=MIB))

    assert raised.value.result.output_exceeded
    assert 0 < len(raised.value.result.stdout) <= MIB


@pytest.mark.unit
def test_a_tool_past_its_timeout_is_stopped(start_server, tmp_path):
    server = start_server()

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="timed out") as raised:
        _python(server, "import time; time.sleep(60)", tmp_path / "work", timeout=2)

    assert type(raised.value) is RuntimeError
    assert time.monotonic() - started < 20
    assert _runs(server) == []


@pytest.mark.unit
def test_a_cancel_stops_the_tool_before_it_returns(start_server, tmp_path):
    server = start_server()
    workdir = tmp_path / "work"

    started = time.monotonic()
    with pytest.raises(SandboxCancelled):
        _python(server, "import time; open('started', 'w').close(); time.sleep(60)", workdir,
                cancel=lambda: os.path.exists(workdir / "started"))

    assert time.monotonic() - started < 20
    # answered once the tool's cgroup, and everything in it, was gone
    assert _runs(server) == []


@pytest.mark.unit
def test_a_run_waits_for_memory_other_runs_hold(start_server, tmp_path):
    server = start_server(budget=256 * MIB)
    first, outcome = _in_background(lambda: _python(server, "import time; time.sleep(3); print('first')",
                                                    tmp_path / "first"))
    wait_for_condition(lambda: server._reserved == 256 * MIB, timeout=10)

    result = _python(server, "print('second')", tmp_path / "second", timeout=30)

    first.join(30)
    assert outcome["result"].stdout == "first\n"
    assert result.stdout == "second\n"


@pytest.mark.unit
def test_a_run_that_waits_out_its_time_for_memory_is_busy(start_server, tmp_path):
    server = start_server(budget=256 * MIB)
    first, _ = _in_background(lambda: _python(server, "import time; time.sleep(8)", tmp_path / "first"))
    wait_for_condition(lambda: server._reserved == 256 * MIB, timeout=10)

    with pytest.raises(ToolRunnerBusy, match="taken by other runs"):
        _python(server, "print('second')", tmp_path / "second", timeout=2)

    first.join(30)


@pytest.mark.unit
def test_a_memory_limit_larger_than_the_runner_has_is_refused(start_server, tmp_path):
    server = start_server(budget=128 * MIB)

    with pytest.raises(ToolRunnerFailed, match=f"more than the {128 * MIB} bytes the tool runner has"):
        _python(server, "print('never')", tmp_path / "work", config=SandboxConfig(memory_limit=256 * MIB))


@pytest.mark.unit
def test_nothing_serving_the_socket_is_unavailable(socket_dir, tmp_path):
    with pytest.raises(ToolRunnerUnavailable, match="is unavailable"):
        run_on_runner(["/usr/bin/true"], env={}, cwd=str(tmp_path), workdir=str(tmp_path),
                      timeout=datetime.timedelta(seconds=5), config=SandboxConfig(),
                      socket_path=os.path.join(socket_dir, "none.sock"))


@pytest.mark.unit
def test_stopping_the_runner_stops_its_runs(start_server, tmp_path):
    server = start_server()
    workdir = tmp_path / "work"
    run, outcome = _in_background(lambda: _python(server, "import time; open('started', 'w').close(); time.sleep(60)",
                                                  workdir))
    wait_for_condition(lambda: os.path.exists(workdir / "started"), timeout=20)

    started = time.monotonic()
    server.stop()
    server.wait_until_stopped()
    run.join(30)

    assert time.monotonic() - started < STOP_SECONDS
    assert isinstance(outcome["error"], ToolRunnerUnavailable)
    assert "stopped" in str(outcome["error"])
    assert not os.path.exists(server.socket_path)


@pytest.mark.unit
def test_a_malformed_request_is_answered_and_the_runner_keeps_serving(start_server, tmp_path, caplog):
    server = start_server()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(server.socket_path)
        send_json(sock, {"v": protocol.PROTOCOL_VERSION, "argv": []})
        response = recv_json(sock, 1024 * 1024)

    assert response["status"] == protocol.STATUS_BAD_REQUEST
    assert "argv" in response["message"]
    assert any("rejected a request" in r.getMessage() for r in caplog.records)
    assert _python(server, "print('next')", tmp_path / "work").stdout == "next\n"


@pytest.mark.unit
def test_a_client_that_sends_nothing_does_not_stop_the_runner(start_server, tmp_path, caplog):
    server = start_server()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(server.socket_path)

    wait_for_condition(lambda: any("received no valid request" in r.getMessage() for r in caplog.records), timeout=10)
    assert _python(server, "print('next')", tmp_path / "work").stdout == "next\n"


@pytest.mark.unit
def test_a_cgroup_that_cannot_be_created_is_an_error(start_server, tmp_path, monkeypatch, caplog):
    server = start_server()

    def failing(memory_max):
        raise OSError("no space")

    monkeypatch.setattr(server.cgroups, "create", failing)

    with pytest.raises(ToolRunnerFailed, match="unable to create a cgroup for it: no space"):
        _python(server, "print('never')", tmp_path / "work")

    [record] = [r for r in caplog.records if "unable to create a cgroup" in r.getMessage()]
    assert record.levelno == logging.ERROR
    assert record.exc_info
    assert server._reserved == 0


@pytest.mark.unit
def test_the_runner_does_not_start_without_landlock(socket_dir, monkeypatch):
    monkeypatch.setattr(server_module, "landlock_available", lambda: False)
    server = ToolRunnerServer(os.path.join(socket_dir, "runner.sock"), io_timeout=5)

    with pytest.raises(RuntimeError, match="landlock is unavailable"):
        server.start()

    assert not os.path.exists(server.socket_path)


@pytest.mark.unit
def test_the_runner_does_not_start_without_a_delegated_cgroup(socket_dir, monkeypatch):
    def undelegated():
        raise CgroupUnavailable("no subtree")

    monkeypatch.setattr(RunCgroups, "delegated", undelegated)
    server = ToolRunnerServer(os.path.join(socket_dir, "runner.sock"), io_timeout=5)

    with pytest.raises(CgroupUnavailable, match="no subtree"):
        server.start()

    assert not os.path.exists(server.socket_path)


@pytest.mark.unit
def test_wait_returns_once_stopped(start_server):
    server = start_server()
    waiter, _ = _in_background(server.wait_until_stopped)

    waiter.join(1)
    assert waiter.is_alive()

    server.stop()
    waiter.join(10)
    assert not waiter.is_alive()


def _fake_server(socket_dir: str, answer):
    """A server that reads one request and answers with answer(), or closes the connection when it is None."""
    path = os.path.join(socket_dir, "fake.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        with conn:
            recv_json(conn, protocol.MAX_REQUEST_BYTES)
            response = answer()
            if response is not None:
                send_json(conn, response)
        listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return path


def _run_against(path: str, tmp_path, timeout: float = 5):
    return run_on_runner(["/usr/bin/true"], env={}, cwd=str(tmp_path), workdir=str(tmp_path),
                         timeout=datetime.timedelta(seconds=timeout), config=SandboxConfig(), socket_path=path)


@pytest.mark.unit
@pytest.mark.parametrize("response,error,message", [
    ({"status": "weird"}, ToolRunnerFailed, "unknown status 'weird'"),
    ({"status": protocol.STATUS_BAD_REQUEST, "message": "argv"}, ToolRunnerFailed, "rejected the request: argv"),
    ({"status": protocol.STATUS_ERROR, "message": "broken"}, ToolRunnerFailed, "broken"),
    (None, ToolRunnerFailed, "closed the connection without answering"),
])
def test_an_answer_that_is_not_a_result_is_a_failure(socket_dir, tmp_path, response, error, message):
    path = _fake_server(socket_dir, lambda: response)

    with pytest.raises(error, match=message):
        _run_against(path, tmp_path)


@pytest.mark.unit
def test_a_runner_that_never_answers_is_a_failure(socket_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(client_module, "RESPONSE_MARGIN_SECONDS", 1)
    answered = threading.Event()
    path = _fake_server(socket_dir, lambda: answered.wait(10) and None)

    try:
        with pytest.raises(ToolRunnerFailed, match="no answer from the tool runner"):
            _run_against(path, tmp_path, timeout=1)
    finally:
        answered.set()


@pytest.mark.unit
def test_a_cancel_the_runner_answered_too_late_for_is_still_a_cancel(socket_dir, tmp_path):
    # the tool finished as the client shut its side down
    path = _fake_server(socket_dir, lambda: {"status": protocol.STATUS_OK, "returncode": 0, "stdout": "", "stderr": ""})

    with pytest.raises(SandboxCancelled):
        run_on_runner(["/usr/bin/true"], env={}, cwd=str(tmp_path), workdir=str(tmp_path),
                      timeout=datetime.timedelta(seconds=5), config=SandboxConfig(), socket_path=path, cancel=lambda: True)


@pytest.mark.unit
def test_the_client_finds_the_runner_the_suite_started(tmp_path):
    # the suite's own runner (tests/harness.py), which run_sandboxed_tool() uses
    result = run_on_runner([sandbox_python(), "-I", "-c", "print('suite')"], env={"PATH": "/usr/bin:/bin"},
                           cwd=str(tmp_path), workdir=str(tmp_path), timeout=datetime.timedelta(seconds=30),
                           config=SandboxConfig())

    assert os.path.exists(get_socket_path())
    assert result.stdout == "suite\n"


@pytest.mark.unit
@pytest.mark.parametrize("change,message", [
    ({"v": 2}, "unsupported protocol version"),
    ({"argv": "ls"}, "argv must be a non-empty list"),
    ({"env": {"A": 1}}, "env must be an object of strings"),
    ({"cwd": "relative"}, "cwd must be an absolute path"),
    ({"workdir": None}, "workdir must be an absolute path"),
    ({"read_dirs": ["/a", 1]}, "read_dirs must be a list of strings"),
    ({"stdin": 5}, "stdin must be a string"),
    ({"timeout": 0}, "timeout must be a positive number"),
    ({"timeout": True}, "timeout must be a positive number"),
    ({"cpu_seconds": 1.5}, "cpu_seconds must be a positive integer"),
    ({"limits": {"memory_limit": -1}}, "invalid limits"),
    ({"limits": {"work_dir": "x"}}, "invalid limits"),
])
def test_invalid_requests(change, message):
    request = {"v": protocol.PROTOCOL_VERSION, "argv": ["/usr/bin/true"], "env": {}, "cwd": "/", "workdir": "/tmp",
               "read_files": [], "read_dirs": [], "write_dirs": [], "stdin": None, "timeout": 10, "cpu_seconds": None,
               "limits": SandboxConfig().model_dump()}
    assert protocol.validate_request(request) is None

    assert message in protocol.validate_request({**request, **change})
