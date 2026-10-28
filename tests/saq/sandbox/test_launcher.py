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
    EXIT_DEADLINE,
    EXIT_KILLED,
    EXIT_PROCESS_LIMIT,
    EXIT_SANDBOX_FAILURE,
    EXIT_STOPPED,
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


def _launcher_argv(*command: str, max_processes: int | None = 16, deadline: float = 60, tcp_ports: str | None = None,
                   term_grace: float | None = None, unconfined: bool = False) -> list[str]:
    options = [f"--deadline={deadline}"]
    if max_processes is not None:
        options.append(f"--max-processes={max_processes}")
    if tcp_ports is not None:
        options.append(f"--tcp-ports={tcp_ports}")
    if term_grace is not None:
        options.append(f"--term-grace={term_grace}")
    if unconfined:
        options.append("--unconfined")
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

    @pytest.mark.parametrize("options,message", [
        ([], "--deadline"),
        (["--deadline=60", "--max-procs=4"], "unknown option"),
        (["--deadline=60", "--unconfined", "--tcp-ports=443"], "--tcp-ports needs the Landlock domain"),
    ])
    def test_malformed_arguments(self, options, message):
        result = subprocess.run([sandbox_python(), "-I", "-S", LAUNCHER, *options, "--", "/bin/true"],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == EXIT_SANDBOX_FAILURE
        assert "usage" in result.stderr
        assert message in result.stderr

    def test_without_a_process_cap(self):
        code = "import subprocess, sys\n" \
               "for p in [subprocess.Popen([sys.executable, '-c', 'pass']) for _ in range(4)]: p.wait()"
        assert _launch(PYTHON, "-c", code, max_processes=None).returncode == 0

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
        assert process.wait(timeout=15) == EXIT_STOPPED
        process.stdout.close()
        assert not _alive(escaped)

    def test_deadline_kills_the_command(self):
        result = _launch("/bin/sleep", "300", deadline=1)
        assert result.returncode == EXIT_DEADLINE
        assert "past its deadline" in result.stderr

    def test_process_left_running_in_another_group_is_killed_when_the_command_exits(self):
        code = "import subprocess\n" \
               "p = subprocess.Popen(['sleep', '300'], process_group=0)\n" \
               "print(p.pid, flush=True)"
        result = _launch(PYTHON, "-c", code)
        assert result.returncode == 0
        wait_for_condition(lambda: not _alive(int(result.stdout)), timeout=10)

    def test_process_cap(self):
        code = "import subprocess, sys, time\n" \
               "children = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)']) for _ in range(8)]\n" \
               "time.sleep(300)"
        result = _launch(PYTHON, "-c", code, max_processes=4)
        assert result.returncode == EXIT_PROCESS_LIMIT
        assert "more than 4 processes" in result.stderr


# prints its pid, then on SIGTERM prints "stopping" and exits with 7
_STOPS_ON_SIGTERM = """
import os, signal, sys, time
def _term(*args):
    # not print: the SIGTERM can land while the print of the pid is still flushing, and stdout is not reentrant
    os.write(1, b"stopping\\n")
    sys.exit(7)
signal.signal(signal.SIGTERM, _term)
print(os.getpid(), flush=True)
# short sleeps: a SIGTERM that lands before a long one starts would wait for it to end
while True:
    time.sleep(0.1)
"""

_IGNORES_SIGTERM = """
import os, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print(os.getpid(), flush=True)
time.sleep(300)
"""


def _started(*command: str, **kwargs) -> tuple[subprocess.Popen, int]:
    """The launcher, started in a session of its own as the GUI CLI starts it, and the pid the command printed."""
    process = subprocess.Popen(_launcher_argv(*command, **kwargs), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    return process, int(process.stdout.readline())


@pytest.mark.unit
class TestGracefulStop:
    def test_stop_sigterms_the_command_first(self):
        process, _ = _started(PYTHON, "-c", _STOPS_ON_SIGTERM, term_grace=30)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == EXIT_STOPPED
        assert stdout == "stopping\n"
        assert "did not stop" not in stderr

    def test_without_a_grace_the_command_is_killed(self):
        process, _ = _started(PYTHON, "-c", _STOPS_ON_SIGTERM)
        process.send_signal(signal.SIGTERM)
        stdout, _ = process.communicate(timeout=15)
        assert process.returncode == EXIT_STOPPED
        assert stdout == ""

    def test_a_command_that_ignores_sigterm_is_killed_after_the_grace(self):
        process, command = _started(PYTHON, "-c", _IGNORES_SIGTERM, term_grace=0.5)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=15)
        assert process.returncode == EXIT_KILLED
        assert "did not stop within 0.5 seconds of SIGTERM" in stderr
        assert not _alive(command)

    def test_sigterm_reaches_the_commands_group_but_not_the_launcher(self):
        # the command leads a group of its own, so its SIGTERM does not stop the launcher halfway
        code = "import subprocess, sys\n" \
               f"child = subprocess.Popen([sys.executable, '-c', {_STOPS_ON_SIGTERM!r}])\n" \
               "child.wait()"
        process, _ = _started(PYTHON, "-c", code, term_grace=30)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == EXIT_STOPPED
        assert stdout == "stopping\n"
        assert "did not stop" not in stderr

    def test_the_deadline_sigterms_the_command_first(self):
        result = _launch(PYTHON, "-c", _STOPS_ON_SIGTERM, deadline=1, term_grace=30)
        assert result.returncode == EXIT_DEADLINE
        assert result.stdout.splitlines()[1] == "stopping"

    def test_what_left_the_session_is_killed_after_a_graceful_stop(self):
        # the pid _started reads is the one _ESCAPE prints: the escaped process's
        process, escaped = _started(PYTHON, "-c", _ESCAPE + "import time; time.sleep(300)", _marker(), term_grace=30)
        assert _alive(escaped)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=15)
        # the command stopped, but what it left had to be killed, which the caller is told
        assert process.returncode == EXIT_KILLED
        assert "killed 1 processes the command left running" in stderr
        assert "did not stop" not in stderr
        assert not _alive(escaped)

    def test_cleanup_survives_a_closed_output(self):
        # the API worker that read the launcher's output died, and its parent-death SIGTERM arrives
        # with nobody reading: the launcher's own messages must not stop it killing what is left
        code = _ESCAPE + "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)"
        process, escaped = _started(PYTHON, "-c", code, _marker(), term_grace=0.5)
        process.stdout.close()
        process.stderr.close()
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == EXIT_KILLED
        assert not _alive(escaped)


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
@pytest.mark.skipif(landlock_abi() < SCOPE_ABI, reason=f"signal scoping needs Landlock ABI {SCOPE_ABI} (Linux 6.12)")
def test_an_unconfined_command_can_signal_a_process_outside_it():
    code = "import os, sys\nos.kill(int(sys.argv[1]), 0)\nprint('signalled')"
    assert _launch(PYTHON, "-c", code, str(os.getpid()), unconfined=True).stdout.strip() == "signalled"


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
