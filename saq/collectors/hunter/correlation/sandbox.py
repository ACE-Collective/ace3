"""Runs a correlate `type: executable` command inside a Landlock sandbox.

Hunt scripts are written by analysts and by AI agents iterating through the validation API. They
are not hostile, but a mistake in one must not be able to damage ACE or put a secret in front of
whoever wrote it. So every execution:

- gets a private working directory, into which the script and its declared `files:` are copied
  (staged); it is the only place the command can create, modify or delete anything
- can read only the system libraries, the python runtime and a short list of /etc files; nothing
  under SAQ_HOME, the data dir, /auth, the SQL volumes, /home or /proc is readable
- runs under rlimits (memory, file size, open files, CPU seconds)
- runs in its own session, which is killed as a whole when the command exits, times out or
  writes more output than allowed, so nothing it started outlives it

Landlock (https://docs.kernel.org/userspace-api/landlock.html) is an unprivileged kernel access
control: a process restricts itself, the restriction is inherited by every descendant and can
never be lifted. util-linux `setpriv` applies it and `prlimit` sets the rlimits; both ship in the
ACE image, and neither needs a capability or a docker compose change. If the kernel does not
support Landlock, the command fails -- it is never run unsandboxed.
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

from saq.collectors.hunter.loader import get_compiled_hunt_dir
from saq.configuration import get_config
from saq.configuration.schema import ExecutableSandboxConfig
from saq.environment import get_base_dir, get_data_dir
from saq.util import abs_path

SETPRIV = "/usr/bin/setpriv"
PRLIMIT = "/usr/bin/prlimit"

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

# how long to wait for the output readers once the command's session has been killed
_READER_JOIN_SECONDS = 5


def get_sandbox_config() -> ExecutableSandboxConfig:
    return get_config().hunter.correlation.executable


def get_sandbox_root() -> str:
    """The directory that holds every execution's working directory."""
    path = os.path.join(get_data_dir(), get_sandbox_config().work_dir)
    os.makedirs(path, exist_ok=True)
    return path


def _python_dirs() -> list[str]:
    """The python runtime the hunt scripts use: the venv and the interpreter it was built from."""
    return sorted({sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix})


def get_read_dirs() -> list[str]:
    return [path for path in [*SANDBOX_READ_DIRS, *_python_dirs()] if os.path.isdir(path)]


def get_read_files() -> list[str]:
    return [path for path in SANDBOX_READ_FILES if os.path.exists(path)]


def _is_under(path: str, root: str) -> bool:
    return os.path.commonpath([path, root]) == root


def _is_under_any(path: str, roots: list[str]) -> bool:
    return any(_is_under(path, root) for root in roots)


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
            "landlock is unavailable, correlate executable commands cannot run: %s",
            result.stderr.decode(errors="replace").strip(),
        )
        return False

    return True


def get_hunt_source_roots() -> list[str]:
    """Directories a script or a `files:` entry may be staged from.

    These are the hunt repositories (each hunt type rule dir's git_dir, or the rule dir itself)
    and the directory the validation API materializes compiled hunts into. Staging happens outside
    the sandbox, so without this check `files: [/auth/passwords/...]` would copy a secret into the
    working directory where the script can read it. A root that contains SAQ_HOME (for example a
    git_dir of `.`) would expose the whole installation and is ignored.
    """
    candidates = [get_compiled_hunt_dir()]
    for hunt_type in get_config().hunt_types:
        for entry in hunt_type.rule_dirs:
            candidates.append(abs_path(entry.git_dir or entry.rule_dir))

    saq_home = os.path.realpath(get_base_dir())
    roots = []
    for candidate in candidates:
        root = os.path.realpath(candidate)
        if _is_under(saq_home, root):
            logging.warning("ignoring hunt source root %s: it contains SAQ_HOME", root)
            continue

        if root not in roots:
            roots.append(root)

    return roots


def stage_executable(path: str, files: list[str] | None, workdir: str, search_path: str | None = None) -> str:
    """Copy a command's executable and its `files:` into workdir and return the path to execute.

    The copies keep their layout relative to one another, so a script that opens
    `Path(__file__).parent / "data.json"` still finds it. An executable that already lies in the
    sandbox's readable directories (a system binary, the venv's python) runs in place and only its
    files are staged.
    """
    resolved = path
    if os.sep not in path:
        resolved = shutil.which(path, path=search_path)
        if resolved is None:
            raise RuntimeError(f"executable {path} not found")

    # Landlock checks the file a path resolves to, so /bin/echo (via the /bin -> usr/bin symlink)
    # and the venv's python (a symlink to /usr/local/bin/python3.x) are both readable in place
    read_dirs = [os.path.realpath(p) for p in get_read_dirs()]
    run_in_place = _is_under_any(os.path.realpath(resolved), read_dirs)

    sources = [] if run_in_place else [resolved]
    sources.extend(files or [])
    if not sources:
        return resolved

    roots = get_hunt_source_roots()
    real_sources = []
    for source in sources:
        real_source = os.path.realpath(source)
        if not _is_under_any(real_source, roots):
            raise RuntimeError(
                f"{source} is outside the hunt repositories; an executable and its files must live "
                "in a hunt rule directory's repository"
            )

        if not os.path.isfile(real_source):
            raise RuntimeError(f"{source} is not a file")

        real_sources.append(real_source)

    base = os.path.commonpath([os.path.dirname(source) for source in real_sources])
    staged = []
    for real_source in real_sources:
        target = os.path.join(workdir, os.path.relpath(real_source, base))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(real_source, target)
        shutil.copymode(real_source, target)
        staged.append(target)

    return resolved if run_in_place else staged[0]


def build_sandbox_argv(argv: list[str], workdir: str, config: ExecutableSandboxConfig, timeout: datetime.timedelta) -> list[str]:
    """Wrap argv so it runs under the rlimits and the Landlock ruleset."""
    rules = []
    for path in get_read_dirs():
        rules.extend(["--landlock-rule", f"path-beneath:{_READ_DIR}:{path}"])
    for path in get_read_files():
        rules.extend(["--landlock-rule", f"path-beneath:{_READ_FILE}:{path}"])
    rules.extend(["--landlock-rule", "path-beneath:read-file,write-file:/dev/null"])
    rules.extend(["--landlock-rule", f"path-beneath:{_WORKDIR}:{workdir}"])

    return [
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


def run_sandboxed(
    argv: list[str],
    stdin_data: str | None,
    env: dict[str, str],
    workdir: str,
    timeout: datetime.timedelta,
    max_output_bytes: int,
) -> SandboxResult:
    """Run an already-wrapped argv and collect its output.

    The command runs in a new session. Whatever happens -- a normal exit, a timeout, too much
    output -- the whole session is killed before this returns, so a process the command left in
    the background does not survive it. With no stdin_data the command reads /dev/null rather
    than inheriting ACE's stdin.
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
                    _kill_session(process.pid)
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
        _kill_session(process.pid)
        process.wait()

    for thread in threads:
        thread.join(timeout=_READER_JOIN_SECONDS)
        if thread.is_alive():
            # a descendant left the session and still holds the pipe open
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


def create_workdir() -> tempfile.TemporaryDirectory:
    """A fresh private working directory for one execution; use as a context manager."""
    return tempfile.TemporaryDirectory(dir=get_sandbox_root(), prefix="cmd-", ignore_cleanup_errors=True)


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


def sweep_stale_workdirs(max_age: datetime.timedelta = STALE_WORKDIR_AGE):
    """Remove working directories left behind by a process that died mid-command."""
    root = get_sandbox_root()
    cutoff = time.time() - max_age.total_seconds()
    for entry in os.scandir(root):
        try:
            if entry.is_dir(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_mtime < cutoff:
                logging.info("removing stale correlation sandbox directory %s", entry.path)
                _force_rmtree(entry.path)
        except OSError as e:
            logging.warning("unable to remove stale correlation sandbox directory %s: %s", entry.path, e)


def prepare_sandbox():
    """Hunter startup: report whether executable commands can run and clear out stale workdirs."""
    if landlock_available():
        logging.info("correlate executable commands run in a landlock sandbox under %s", get_sandbox_root())
    else:
        logging.error("landlock is unavailable here: every correlate executable command will fail")

    try:
        sweep_stale_workdirs()
    except OSError as e:
        logging.warning("unable to sweep the correlation sandbox directory: %s", e)
