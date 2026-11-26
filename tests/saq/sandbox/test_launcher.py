"""launcher.py on its own, and run_sandboxed driving it.

Most of this needs no Landlock: the launcher is run around plain commands, without the prlimit and
setpriv stages build_sandbox_argv adds. The TCP port and signal-scope tests are the exception and
are skipped on a kernel older than the Landlock ABI they need.
"""

import datetime
import json
import mmap
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
    EXIT_MEMORY_LIMIT,
    EXIT_PROCESS_LIMIT,
    EXIT_SANDBOX_FAILURE,
    EXIT_STOPPED,
    NET_ABI,
    SCOPE_ABI,
    landlock_abi,
    memory_used,
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
                   term_grace: float | None = None, unconfined: bool = False,
                   memory_limit: int | None = None) -> list[str]:
    options = [f"--deadline={deadline}"]
    if max_processes is not None:
        options.append(f"--max-processes={max_processes}")
    if memory_limit is not None:
        options.append(f"--memory-limit={memory_limit}")
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


def _launch_with_status(*command: str, timeout: float = 30, **kwargs) -> tuple[subprocess.CompletedProcess, list[dict]]:
    """The launcher run with --status-fd, and the verdicts it wrote there."""
    read_end, write_end = os.pipe()
    try:
        argv = _launcher_argv(*command, **kwargs)
        argv.insert(argv.index(LAUNCHER) + 1, f"--status-fd={write_end}")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, pass_fds=(write_end,))
        os.close(write_end)
        write_end = None
        with os.fdopen(read_end, "r") as fp:
            read_end = None
            return result, [json.loads(line) for line in fp.read().splitlines()]
    finally:
        for fd in (read_end, write_end):
            if fd is not None:
                os.close(fd)


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


MIB = 1024 ** 2

# writes to every page of argv[1] MiB of private memory (b"x" * n), or of shared memory with "shared"
# (an anonymous mmap is MAP_SHARED), prints "allocated" and waits to be killed
_ALLOCATE = """
import mmap, sys, time
size = int(sys.argv[1]) * 1024 ** 2
if sys.argv[2:] == ["shared"]:
    memory = mmap.mmap(-1, size)
    memory.write(b"x" * size)
else:
    memory = b"x" * size
print("allocated", flush=True)
time.sleep(300)
"""

# starts argv[1] children that each run _ALLOCATE with argv[2] MiB, prints their pids and waits
_CHILDREN_ALLOCATE = f"""
import subprocess, sys, time
children = [subprocess.Popen([sys.executable, "-c", {_ALLOCATE!r}, sys.argv[2]], stdout=subprocess.DEVNULL)
            for _ in range(int(sys.argv[1]))]
print(" ".join(str(child.pid) for child in children), flush=True)
time.sleep(300)
"""


@pytest.mark.unit
class TestMemoryLimit:
    def test_reserved_address_space_is_not_counted(self):
        # what the .NET GC, the JVM and OpenBLAS's threads do at start: reserve far more than they use
        code = ("import mmap\n"
                "reserved = mmap.mmap(-1, 64 * 1024 ** 3, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=0)\n"
                "print('started')")
        result = _launch(PYTHON, "-c", code, memory_limit=256 * MIB)
        assert result.returncode == 0, result.stderr
        assert result.stdout == "started\n"

    def test_a_command_under_its_limit_runs(self):
        code = "x = b'x' * (64 * 1024 ** 2)\nprint('done')"
        result = _launch(PYTHON, "-c", code, memory_limit=256 * MIB)
        assert result.returncode == 0, result.stderr
        assert result.stdout == "done\n"

    @pytest.mark.parametrize("kind", ["private", "shared"])
    def test_a_command_that_uses_more_than_its_limit_is_killed(self, kind):
        result = _launch(PYTHON, "-c", _ALLOCATE, "512", kind, memory_limit=256 * MIB)
        assert result.returncode == EXIT_MEMORY_LIMIT
        used = int(result.stderr.split("sandbox: the command used ")[1].split()[0])
        assert used > 256 * MIB
        assert f"more than its limit of {256 * MIB} bytes" in result.stderr

    def test_the_memory_of_every_process_it_started_is_counted(self):
        # four children of 100 MiB, each under the limit alone
        process, pids = _started_children(4, 100, memory_limit=256 * MIB)
        assert process.wait(timeout=30) == EXIT_MEMORY_LIMIT
        assert "more than its limit" in process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        assert not any(_alive(pid) for pid in pids)

    def test_a_child_that_allocates_is_killed_with_the_command(self):
        process, [pid] = _started_children(1, 512, memory_limit=256 * MIB)
        assert process.wait(timeout=30) == EXIT_MEMORY_LIMIT
        process.stdout.close()
        process.stderr.close()
        assert not _alive(pid)

    def test_the_command_is_what_the_oom_killer_takes_first(self):
        result = _launch("/bin/cat", "/proc/self/oom_score_adj", memory_limit=256 * MIB)
        assert result.stdout.strip() == "1000"

    def test_without_a_limit_the_command_keeps_the_launchers_oom_score(self):
        # the GUI CLI runs `ace` without one
        with open("/proc/self/oom_score_adj") as fp:
            ours = fp.read().strip()
        assert _launch("/bin/cat", "/proc/self/oom_score_adj").stdout.strip() == ours


@pytest.mark.unit
def test_memory_used_counts_what_is_written_and_not_what_is_reserved():
    before = memory_used([os.getpid()])
    reserved = mmap.mmap(-1, 16 * 1024 ** 3, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=0)
    assert memory_used([os.getpid()]) - before < 64 * MIB
    written = b"x" * (128 * MIB)
    assert memory_used([os.getpid()]) - before >= 128 * MIB
    del written
    reserved.close()


def _swap_active() -> bool:
    with open("/proc/swaps") as fp:
        return len(fp.read().splitlines()) > 1  # the first line is the header


def _vm_swap() -> int:
    with open("/proc/self/status", "rb") as fp:
        for line in fp:
            if line.startswith(b"VmSwap:"):
                return int(line.split()[1]) * 1024
    return 0


_MADV_PAGEOUT = 21  # Linux 5.4; this Python does not export it


@pytest.mark.unit
@pytest.mark.skipif(not _swap_active(), reason="no swap to page out to")
def test_memory_used_counts_what_is_swapped_out():
    # under memory pressure the kernel swaps a tool's pages out, and they still count against its limit
    before = memory_used([os.getpid()])
    swap_before = _vm_swap()
    written = mmap.mmap(-1, 128 * MIB, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    try:
        written.write(b"\x5a" * (128 * MIB))  # not zero, so the pages are not deduplicated
        written.madvise(_MADV_PAGEOUT)
        if _vm_swap() - swap_before < 64 * MIB:
            pytest.skip("the kernel did not page the memory out")
        assert memory_used([os.getpid()]) - before >= 128 * MIB
    finally:
        written.close()


@pytest.mark.unit
def test_memory_used_skips_a_process_that_is_gone():
    process = subprocess.Popen(["/bin/true"])
    process.wait()
    assert memory_used([process.pid]) == 0


def _started_children(count: int, mib: int, **kwargs) -> tuple[subprocess.Popen, list[int]]:
    process = subprocess.Popen(_launcher_argv(PYTHON, "-c", _CHILDREN_ALLOCATE, str(count), str(mib), **kwargs),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    return process, [int(pid) for pid in process.stdout.readline().split()]


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

    def test_refused_where_the_kernel_cannot_enforce_it(self, listeners):
        # run on any kernel: the launcher is told its kernel has no TCP port rules
        older_kernel = ("import sys\n"
                        "sys.path.insert(0, sys.argv.pop(1))\n"
                        "import launcher\n"
                        "launcher.landlock_abi = lambda: launcher.NET_ABI - 1\n"
                        "sys.exit(launcher.main(sys.argv[1:]))")
        result = subprocess.run([sandbox_python(), "-I", "-S", "-c", older_kernel, os.path.dirname(LAUNCHER),
                                 "--deadline=60", f"--tcp-ports={listeners[0]}", "--", PYTHON, "-c", _CONNECT,
                                 str(listeners[0])], capture_output=True, text=True, timeout=30)
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


@pytest.mark.unit
class TestStatusFd:
    """The launcher's verdict on --status-fd, which a command cannot write and which is written only when the
    launcher ended the command itself."""

    def test_a_command_that_exits_on_its_own_gets_no_verdict(self):
        # even with the codes the launcher uses, and its line on stderr
        code = (f"import sys\nsys.stderr.write('sandbox: the command used 999 bytes of memory, more than its limit of 1 bytes\\n')\n"
                f"sys.exit({EXIT_MEMORY_LIMIT})")
        result, verdicts = _launch_with_status(PYTHON, "-c", code, memory_limit=256 * MIB)
        assert result.returncode == EXIT_MEMORY_LIMIT
        assert verdicts == []

    def test_memory_limit(self):
        result, [verdict] = _launch_with_status(PYTHON, "-c", _ALLOCATE, "512", memory_limit=256 * MIB)
        assert result.returncode == EXIT_MEMORY_LIMIT
        assert verdict["reason"] == "memory_limit"
        assert verdict["exit_code"] == EXIT_MEMORY_LIMIT
        assert verdict["memory_limit"] == 256 * MIB
        assert verdict["memory_used"] > 256 * MIB
        # the stderr line stays, for whoever reads the tool's output
        assert f"used {verdict['memory_used']} bytes of memory" in result.stderr

    def test_deadline(self):
        result, verdicts = _launch_with_status("/bin/sleep", "300", deadline=1)
        assert result.returncode == EXIT_DEADLINE
        assert verdicts == [{"reason": "deadline", "exit_code": EXIT_DEADLINE}]

    def test_process_limit(self):
        code = "import subprocess, sys, time\n" \
               "children = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)']) for _ in range(8)]\n" \
               "time.sleep(300)"
        result, verdicts = _launch_with_status(PYTHON, "-c", code, max_processes=4)
        assert result.returncode == EXIT_PROCESS_LIMIT
        assert verdicts == [{"reason": "process_limit", "exit_code": EXIT_PROCESS_LIMIT, "max_processes": 4}]

    def test_a_command_that_cannot_run(self):
        result, verdicts = _launch_with_status("/nonexistent/command")
        assert result.returncode == EXIT_SANDBOX_FAILURE
        [verdict] = verdicts
        assert verdict["reason"] == "sandbox_failure"
        assert verdict["exit_code"] == EXIT_SANDBOX_FAILURE
        assert verdict["message"].startswith("cannot run /nonexistent/command: ")

    def test_malformed_arguments(self):
        result, verdicts = _launch_with_status("/bin/true", max_processes="many")
        assert result.returncode == EXIT_SANDBOX_FAILURE
        [verdict] = verdicts
        assert verdict["reason"] == "sandbox_failure"
        assert "usage" in verdict["message"]

    def test_stopped(self, tmp_path):
        read_end, write_end = os.pipe()
        argv = _launcher_argv(PYTHON, "-c", "print('started', flush=True)\nimport time\ntime.sleep(300)")
        argv.insert(argv.index(LAUNCHER) + 1, f"--status-fd={write_end}")
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, pass_fds=(write_end,), start_new_session=True)
        os.close(write_end)
        with os.fdopen(read_end) as status:
            assert process.stdout.readline() == "started\n"
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=15) == EXIT_STOPPED
            process.stdout.close()
            assert json.loads(status.read()) == {"reason": "stopped", "exit_code": EXIT_STOPPED}

    def test_the_command_does_not_inherit_it(self):
        read_end, write_end = os.pipe()
        try:
            argv = _launcher_argv("/bin/ls", "/proc/self/fd")
            argv.insert(argv.index(LAUNCHER) + 1, f"--status-fd={write_end}")
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30, pass_fds=(write_end,))
        finally:
            os.close(read_end)
            os.close(write_end)
        assert result.returncode == 0, result.stderr
        assert str(write_end) not in result.stdout.split()

    def test_a_status_fd_that_is_not_open(self):
        argv = _launcher_argv("/bin/true")
        argv.insert(argv.index(LAUNCHER) + 1, "--status-fd=1000")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert result.returncode == EXIT_SANDBOX_FAILURE
        assert "--status-fd" in result.stderr


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
