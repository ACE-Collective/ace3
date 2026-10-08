"""launcher.py on its own, and run_sandboxed driving it.

Most of this needs no Landlock: the launcher is run around plain commands, without the prlimit and
setpriv stages build_sandbox_argv adds. The TCP port and signal-scope tests are the exception and
are skipped on a kernel older than the Landlock ABI they need.
"""

import datetime
import os
import signal
import socket
import subprocess
import sys
import uuid

import pytest

from saq.configuration.schema import SandboxConfig
from saq.sandbox.launcher import (
    EXIT_SANDBOX_FAILURE,
    NET_ABI,
    SCOPE_ABI,
    landlock_abi,
)
from saq.sandbox.runner import LAUNCHER, SETPRIV, build_sandbox_argv, run_sandboxed, sandbox_python
from tests.saq.helpers import wait_for_condition

PYTHON = sys.executable

# starts a process in a new session, the way a script would daemonize something, and prints its pid
_ESCAPE = """
import subprocess, sys
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)", sys.argv[1]],
                         start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(child.pid, flush=True)
"""


def _launcher_argv(*command: str, max_processes: int = 16, deadline: float = 60, tcp_ports: str | None = None) -> list[str]:
    options = [f"--max-processes={max_processes}", f"--deadline={deadline}"]
    if tcp_ports is not None:
        options.append(f"--tcp-ports={tcp_ports}")
    return [sandbox_python(), "-I", "-S", LAUNCHER, *options, "--", *command]


def _launch(*command: str, stdin: str | None = None, timeout: float = 30, cwd: str | None = None, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(_launcher_argv(*command, **kwargs), input=stdin, capture_output=True, text=True,
                          timeout=timeout, cwd=cwd)


def _alive(pid: int) -> bool:
    """True while pid is a live process (a zombie counts as gone)."""
    try:
        with open(f"/proc/{pid}/stat") as fp:
            return fp.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def _marker() -> str:
    return f"launcher-marker-{uuid.uuid4().hex}"


@pytest.mark.unit
class TestExitStatus:
    def test_exit_code_is_the_commands(self):
        assert _launch("/bin/sh", "-c", "exit 3").returncode == 3

    def test_command_killed_by_a_signal(self):
        assert _launch("/bin/sh", "-c", "kill -9 $$").returncode == 128 + signal.SIGKILL

    def test_output_and_input_pass_through(self):
        result = _launch("/bin/sh", "-c", "cat; echo err >&2", stdin="hello\n")
        assert result.stdout == "hello\n"
        assert result.stderr == "err\n"

    def test_command_that_cannot_run(self):
        result = _launch("/nonexistent/command")
        assert result.returncode == EXIT_SANDBOX_FAILURE
        assert "cannot run /nonexistent/command" in result.stderr

    def test_malformed_arguments(self):
        result = subprocess.run([sandbox_python(), "-I", "-S", LAUNCHER, "--", "/bin/true"],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == EXIT_SANDBOX_FAILURE
        assert "usage" in result.stderr

    def test_ignored_signals_are_reset_for_the_command(self):
        # python ignores SIGPIPE and SIGXFSZ; the command must get the defaults (RLIMIT_FSIZE relies on SIGXFSZ)
        result = _launch("/bin/sh", "-c", "grep SigIgn /proc/self/status")
        ignored = int(result.stdout.split()[1], 16)
        assert not ignored & (1 << (signal.SIGPIPE - 1))
        assert not ignored & (1 << (signal.SIGXFSZ - 1))


@pytest.mark.unit
class TestCleanup:
    def test_process_that_left_the_session_is_killed_when_the_command_exits(self):
        result = _launch(PYTHON, "-c", _ESCAPE, _marker())
        assert result.returncode == 0
        escaped = int(result.stdout)
        wait_for_condition(lambda: not _alive(escaped), timeout=10)

    def test_stop_kills_the_command_and_what_left_its_session(self):
        process = subprocess.Popen(
            _launcher_argv(PYTHON, "-c", _ESCAPE + "import time; time.sleep(300)", _marker()),
            stdout=subprocess.PIPE, text=True, start_new_session=True,
        )
        escaped = int(process.stdout.readline())
        assert _alive(escaped)

        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == EXIT_SANDBOX_FAILURE
        process.stdout.close()
        assert not _alive(escaped)

    def test_deadline_kills_the_command(self):
        result = _launch("/bin/sleep", "300", deadline=1)
        assert result.returncode == EXIT_SANDBOX_FAILURE
        assert "past its deadline" in result.stderr

    def test_process_cap(self):
        code = "import subprocess, sys, time\n" \
               "children = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)']) for _ in range(8)]\n" \
               "time.sleep(300)"
        result = _launch(PYTHON, "-c", code, max_processes=4)
        assert result.returncode == EXIT_SANDBOX_FAILURE
        assert "more than 4 processes" in result.stderr


# connects to each port given on 127.0.0.1 and prints port:outcome
_CONNECT = """
import socket, sys
for port in sys.argv[1:]:
    try:
        socket.create_connection(("127.0.0.1", int(port)), timeout=5).close()
        print(f"{port}:connected")
    except OSError as e:
        print(f"{port}:{type(e).__name__}")
"""


@pytest.fixture
def listeners():
    """Two listening TCP ports on 127.0.0.1."""
    sockets = []
    for _ in range(2):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        sockets.append(listener)
    try:
        yield [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


@pytest.mark.unit
class TestTcpPorts:
    def test_without_tcp_ports_tcp_is_unrestricted(self, listeners):
        allowed, other = listeners
        result = _launch(PYTHON, "-c", _CONNECT, str(allowed), str(other))
        assert result.stdout.split() == [f"{allowed}:connected", f"{other}:connected"]

    @pytest.mark.skipif(landlock_abi() >= NET_ABI, reason="checks the refusal on a kernel without TCP port rules")
    def test_refused_where_the_kernel_cannot_enforce_it(self, listeners):
        result = _launch(PYTHON, "-c", _CONNECT, str(listeners[0]), tcp_ports=str(listeners[0]))
        assert result.returncode == EXIT_SANDBOX_FAILURE
        assert "cannot restrict TCP ports" in result.stderr
        assert result.stdout == ""

    @pytest.mark.skipif(landlock_abi() < NET_ABI, reason=f"TCP port rules need Landlock ABI {NET_ABI} (Linux 6.7)")
    def test_connections_limited_to_the_allowed_ports(self, listeners):
        allowed, other = listeners
        result = _launch(PYTHON, "-c", _CONNECT, str(allowed), str(other), tcp_ports=f"{allowed},53")
        assert result.stdout.split() == [f"{allowed}:connected", f"{other}:PermissionError"]

    @pytest.mark.skipif(landlock_abi() < NET_ABI, reason=f"TCP port rules need Landlock ABI {NET_ABI} (Linux 6.7)")
    def test_empty_list_allows_no_tcp(self, listeners):
        result = _launch(PYTHON, "-c", _CONNECT, str(listeners[0]), tcp_ports="")
        assert result.stdout.split() == [f"{listeners[0]}:PermissionError"]

    def test_build_sandbox_argv_passes_the_configured_ports(self, tmpdir):
        config = SandboxConfig(allowed_tcp_ports=[443, 53])
        argv = build_sandbox_argv(["/bin/true"], str(tmpdir), config, datetime.timedelta(seconds=5))
        assert "--tcp-ports=443,53" in argv[:argv.index("--")]

        config = config.model_copy(update={"allowed_tcp_ports": None})
        argv = build_sandbox_argv(["/bin/true"], str(tmpdir), config, datetime.timedelta(seconds=5))
        assert not any(arg.startswith("--tcp-ports") for arg in argv)


@pytest.mark.unit
@pytest.mark.skipif(landlock_abi() < SCOPE_ABI, reason=f"signal scoping needs Landlock ABI {SCOPE_ABI} (Linux 6.12)")
def test_command_cannot_signal_a_process_outside_it():
    code = "import os, sys\ntry:\n    os.kill(int(sys.argv[1]), 0)\n    print('signalled')\nexcept PermissionError:\n    print('refused')"
    # the test process is outside the command's domain; the launcher's own child is inside it
    assert _launch(PYTHON, "-c", code, str(os.getpid())).stdout.strip() == "refused"
    assert _launch("/bin/sh", "-c", "kill -0 $$ && echo signalled").stdout.strip() == "signalled"


@pytest.mark.unit
@pytest.mark.parametrize("tcp_ports", [
    pytest.param(None, marks=pytest.mark.skipif(landlock_abi() < SCOPE_ABI, reason=f"signal scoping needs Landlock ABI {SCOPE_ABI} (Linux 6.12)")),
    pytest.param("443", marks=pytest.mark.skipif(landlock_abi() < NET_ABI, reason=f"TCP port rules need Landlock ABI {NET_ABI} (Linux 6.7)")),
])
def test_domain_allows_cross_directory_rename(tmp_path, tcp_ports):
    # every Landlock domain denies REFER unless a rule allows it, which only shows once a domain
    # that handles filesystem access is nested inside the launcher's, as setpriv's is in the
    # sandbox; this one allows REFER in tmp_path, so only the launcher's domain could deny it
    code = "import os\nopen('a', 'w').close()\nos.mkdir('sub')\nos.rename('a', 'sub/a')\nos.link('sub/a', 'b')"
    result = _launch(SETPRIV, "--landlock-access", "fs:refer", "--landlock-rule", f"path-beneath:refer:{tmp_path}",
                     "--", PYTHON, "-c", code, cwd=str(tmp_path), tcp_ports=tcp_ports)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "sub" / "a").exists() and (tmp_path / "b").exists()


@pytest.mark.unit
class TestRunSandboxed:
    """run_sandboxed's side of the protocol: it asks the launcher to stop instead of killing it."""

    def test_timeout_kills_what_left_the_session(self, tmpdir):
        marker = _marker()
        argv = _launcher_argv(PYTHON, "-c", _ESCAPE + "import time; time.sleep(300)", marker)
        with pytest.raises(RuntimeError, match="timed out"):
            run_sandboxed(argv, None, dict(os.environ), str(tmpdir), datetime.timedelta(seconds=3), 1024 * 1024)

        wait_for_condition(lambda: not _pids_with(marker), timeout=10)

    def test_too_much_output_kills_what_left_the_session(self, tmpdir):
        marker = _marker()
        code = _ESCAPE + "import sys\nwhile True: sys.stdout.write('x' * 65536)"
        argv = _launcher_argv(PYTHON, "-c", code, marker)
        with pytest.raises(RuntimeError, match="more than"):
            run_sandboxed(argv, None, dict(os.environ), str(tmpdir), datetime.timedelta(seconds=30), 1024 * 1024)

        wait_for_condition(lambda: not _pids_with(marker), timeout=10)


def _pids_with(marker: str) -> list[int]:
    """Live processes whose command line contains marker."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fp:
                if marker.encode() not in fp.read():
                    continue
        except OSError:
            continue
        if _alive(int(entry)):
            pids.append(int(entry))
    return pids
