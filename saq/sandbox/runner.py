"""Runs a command inside a Landlock sandbox.

The commands that run here are not trusted to be careful, and a mistake in one must not be able to
damage ACE or put a secret in front of whoever wrote it. So every command:

- runs in a private working directory, the only place it can create, modify or delete anything;
  the caller copies in whatever the command needs
- can read only the system libraries, the python runtime and a short list of /etc files; nothing
  under SAQ_HOME, the data dir, /auth, the SQL volumes, /home or /proc is readable
- runs under rlimits (memory, file size, open files, CPU seconds)
- can open TCP connections only to the caller's `allowed_tcp_ports`, which keeps it off the cloud
  metadata endpoint and ACE's own services
- runs under launcher.py, which kills everything the command started when it exits, times out or
  writes more output than allowed (even a process that left the session), kills a command that
  starts more than `max_processes` processes, and on Linux 6.12+ keeps the command from signalling
  any process outside it

Landlock (https://docs.kernel.org/userspace-api/landlock.html) is an unprivileged kernel access
control: a process restricts itself, the restriction is inherited by every descendant and can
never be lifted. util-linux `setpriv` applies it and `prlimit` sets the rlimits; both ship in the
ACE image, and neither needs a capability or a docker compose change. If the kernel does not
support Landlock, a caller must not run the command at all (landlock_available()).
"""

import datetime
import functools
import logging
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass

from saq.configuration.schema import SandboxConfig

SETPRIV = "/usr/bin/setpriv"
PRLIMIT = "/usr/bin/prlimit"
LAUNCHER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "launcher.py")

_READ_DIR = "read-file,read-dir,execute"
# Landlock rejects directory rights on a rule for a single file
_READ_FILE = "read-file"
_WORKDIR = (
    "read-file,read-dir,execute,write-file,truncate,remove-file,remove-dir,"
    "make-reg,make-dir,make-sym,make-fifo,make-sock,refer"
)

# Everything a sandboxed command can read besides its own working directory. The list is closed:
# Landlock denies whatever is not named here, so a secret added to the container later is
# unreadable without anyone having to remember to hide it. Keep it that way -- never add /etc as a
# whole (/etc/environment carries SAQ_ENC and service passwords), SAQ_HOME, the data dir, /auth,
# /home, /proc or /tmp. /usr covers /bin, /lib, /lib64 and /usr/local through their symlinks.
SANDBOX_READ_DIRS = (
    "/usr",
    "/etc/ssl",
    "/etc/ca-certificates",
)
SANDBOX_READ_FILES = (
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/localtime",
    "/etc/passwd",
    "/etc/group",
    "/etc/ld.so.cache",
    "/etc/mime.types",
    "/dev/urandom",
    "/dev/random",
    "/dev/zero",
)

# how much of stderr is kept in the error raised for a failed command
STDERR_TAIL_BYTES = 16 * 1024

# a sandbox working directory older than this was left behind by a process that died mid-command
STALE_WORKDIR_AGE = datetime.timedelta(hours=24)

# how long to wait for the output readers once the launcher has exited
_READER_JOIN_SECONDS = 5

# how long the launcher gets to kill what the command started once it is told to stop
_LAUNCHER_STOP_SECONDS = 10

# the launcher kills the command itself this long after its timeout, for when the ACE process
# that started it is gone (a recycled or killed API worker) and cannot tell it to stop
_LAUNCHER_DEADLINE_GRACE = datetime.timedelta(seconds=30)


def _python_dirs() -> list[str]:
    """The python runtime: the venv and the interpreter it was built from."""
    return sorted({sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix})


def get_read_dirs() -> list[str]:
    return [path for path in [*SANDBOX_READ_DIRS, *_python_dirs()] if os.path.isdir(path)]


def get_read_files() -> list[str]:
    return [path for path in SANDBOX_READ_FILES if os.path.exists(path)]


@functools.cache
def landlock_available() -> bool:
    """True when setpriv can apply a Landlock ruleset here (cached for the life of the process)."""
    try:
        result = subprocess.run(
            [SETPRIV, "--no-new-privs", "--landlock-access", "fs",
             "--landlock-rule", f"path-beneath:{_READ_DIR}:/usr", "--", "/usr/bin/true"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logging.error("unable to probe for landlock support: %s", e)
        return False

    if result.returncode != 0:
        logging.error(
            "landlock is unavailable, sandboxed commands cannot run: %s",
            result.stderr.decode(errors="replace").strip(),
        )
        return False

    return True


def sandbox_python() -> str:
    """The venv's interpreter; under uwsgi, sys.executable is not python."""
    python = os.path.join(sys.exec_prefix, "bin", "python3")
    return python if os.path.exists(python) else sys.executable


def build_sandbox_argv(argv: list[str], workdir: str, config: SandboxConfig, timeout: datetime.timedelta) -> list[str]:
    """Wrap argv so it runs under the launcher, the rlimits and the Landlock ruleset."""
    rules = []
    for path in get_read_dirs():
        rules.extend(["--landlock-rule", f"path-beneath:{_READ_DIR}:{path}"])
    for path in get_read_files():
        rules.extend(["--landlock-rule", f"path-beneath:{_READ_FILE}:{path}"])
    rules.extend(["--landlock-rule", "path-beneath:read-file,write-file:/dev/null"])
    rules.extend(["--landlock-rule", f"path-beneath:{_WORKDIR}:{workdir}"])

    launcher_options = [
        f"--max-processes={config.max_processes}",
        f"--deadline={(timeout + _LAUNCHER_DEADLINE_GRACE).total_seconds()}",
    ]
    if config.allowed_tcp_ports is not None:
        launcher_options.append(f"--tcp-ports={','.join(str(port) for port in config.allowed_tcp_ports)}")

    return [
        sandbox_python(), "-I", "-S", LAUNCHER,
        *launcher_options,
        "--",
        PRLIMIT,
        f"--as={config.memory_limit}",
        f"--fsize={config.file_size_limit}",
        f"--nofile={config.open_files_limit}",
        f"--cpu={max(1, math.ceil(timeout.total_seconds()))}",
        "--core=0",
        "--",
        SETPRIV, "--no-new-privs", "--landlock-access", "fs", *rules,
        "--",
        *argv,
    ]


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str


def _kill_session(pid: int):
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _stop(process: subprocess.Popen):
    """Tell the launcher to kill everything the command started; it exits once that is done."""
    try:
        process.send_signal(signal.SIGTERM)
    except OSError:
        pass


def run_sandboxed(
    argv: list[str],
    stdin_data: str | None,
    env: dict[str, str],
    workdir: str,
    timeout: datetime.timedelta,
    max_output_bytes: int,
) -> SandboxResult:
    """Run an argv wrapped by build_sandbox_argv and collect its output.

    Whatever happens -- a normal exit, a timeout, too much output -- the launcher has killed
    everything the command started before this returns, so a process the command left in the
    background does not survive it. With no stdin_data the command reads /dev/null rather than
    inheriting ACE's stdin. env is the command's whole environment: pass only what it needs, never
    os.environ (Landlock does not filter the environment, and ACE's carries secrets).
    """
    process = subprocess.Popen(
        argv,
        cwd=workdir,
        env=env,
        stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    output_exceeded = threading.Event()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}

    def _read(stream, buffer: bytearray):
        try:
            while chunk := stream.read1(65536):
                if len(buffer) + len(chunk) > max_output_bytes:
                    output_exceeded.set()
                    _stop(process)
                    return

                buffer.extend(chunk)
        except (OSError, ValueError):
            pass

    def _write():
        try:
            process.stdin.write(stdin_data.encode("utf-8"))
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=_read, args=(process.stdout, buffers["stdout"]), daemon=True),
        threading.Thread(target=_read, args=(process.stderr, buffers["stderr"]), daemon=True),
    ]
    if stdin_data is not None:
        threads.append(threading.Thread(target=_write, daemon=True))

    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout.total_seconds())
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        # a no-op when the launcher has already exited: it cleaned up when the command did
        _stop(process)
        try:
            process.wait(timeout=_LAUNCHER_STOP_SECONDS)
        except subprocess.TimeoutExpired:
            # the launcher itself is stuck; it is still unreaped, so its pid is still its session's
            logging.warning("sandbox launcher for %s did not exit when stopped", argv[-1])
            _kill_session(process.pid)
            process.wait()

    for thread in threads:
        thread.join(timeout=_READER_JOIN_SECONDS)
        if thread.is_alive():
            logging.warning("output reader for sandboxed command %s did not finish", argv[-1])

    for stream in (process.stdout, process.stderr):
        try:
            stream.close()
        except OSError:
            pass

    if timed_out:
        raise RuntimeError(f"command timed out after {timeout}")

    if output_exceeded.is_set():
        raise RuntimeError(f"command wrote more than {max_output_bytes} bytes of output")

    return SandboxResult(
        returncode=process.returncode,
        stdout=buffers["stdout"].decode("utf-8", errors="replace"),
        stderr=buffers["stderr"][-STDERR_TAIL_BYTES:].decode("utf-8", errors="replace"),
    )


def create_workdir(root: str) -> tempfile.TemporaryDirectory:
    """A fresh private working directory under root for one command; use as a context manager.

    root must be on a filesystem that allows execution (not a noexec tmpfs).
    """
    os.makedirs(root, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=root, prefix="cmd-", ignore_cleanup_errors=True)


def _force_rmtree(path: str):
    """rmtree that also removes directories a command made unreadable or unwritable."""
    os.chmod(path, 0o700)
    # os.walk is top-down, so each directory is opened up before the walk descends into it
    for dirpath, dirnames, _ in os.walk(path):
        for dirname in dirnames:
            child = os.path.join(dirpath, dirname)
            if not os.path.islink(child):
                os.chmod(child, 0o700)

    shutil.rmtree(path)


def sweep_stale_workdirs(root: str, max_age: datetime.timedelta = STALE_WORKDIR_AGE):
    """Remove working directories under root left behind by a process that died mid-command."""
    if not os.path.isdir(root):
        return

    cutoff = time.time() - max_age.total_seconds()
    for entry in os.scandir(root):
        try:
            if entry.is_dir(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_mtime < cutoff:
                logging.info("removing stale sandbox directory %s", entry.path)
                _force_rmtree(entry.path)
        except OSError as e:
            logging.warning("unable to remove stale sandbox directory %s: %s", entry.path, e)
