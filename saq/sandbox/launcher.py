"""Supervises one sandboxed command. runner.py starts this instead of the command.

It runs as a script, with the venv's python in isolated mode, so it uses the standard library only:

    python3 -I -S launcher.py --max-processes=64 --memory-limit=4294967296 --deadline=330 --tcp-ports=443,53 \
        -- prlimit ... -- setpriv ... -- command

The GUI CLI (aceapi_v2/cli/service.py) runs `ace` under it too, with --unconfined, which skips the
Landlock domain (an `ace` command may signal and connect to anything a shell could), and with
--term-grace, which stops the command the way docker stops a service: SIGTERM to its process
group, then everything is killed once it has exited or the grace has run out.

Before the exec, the child enters a Landlock domain for what setpriv cannot express (setpriv then
nests its filesystem rules inside it):

- TCP ports. With --tcp-ports, the command can open a TCP connection only to those ports
  (Landlock ABI 4, Linux 6.7). That keeps it off the cloud metadata endpoint (port 80), whose
  instance credentials would undo the rest of the sandbox, and off ACE's own services. UDP, and so
  ordinary DNS, is not affected. On a kernel that cannot enforce it the command is not run.
- Signal scoping. Nothing the command starts can signal, or connect to an abstract unix socket
  of, a process outside the domain (Landlock ABI 6, Linux 6.12): not the ACE process that started
  it, not the other API workers, not this launcher. On an older kernel the scope is skipped, and
  each caller says so at startup (the hunter's prepare_sandbox(), for one).

The domain restricts no filesystem access; restrict_self() says why it still needs one filesystem rule.

The launcher itself forks the command and stays outside that domain, which is what lets it do two
things the command cannot undo:

- Cleanup. It is a child subreaper, so whatever the command starts is reparented to it instead of
  to the container's init, even a process that left the session. When the command exits, when
  ACE sends SIGTERM (timeout, too much output), or at --deadline, every descendant is stopped and
  killed.
- A process cap. A command with more than --max-processes live descendants is killed (no cap
  without it).
- A memory cap. A command whose live descendants together use more than --memory-limit bytes of
  memory is killed (no cap without it). Memory is what the processes have written to, their resident
  anonymous and shared pages, and not the address space they reserve: a .NET GC, a JVM or OpenBLAS's
  threads reserve gigabytes at start that they never touch, which RLIMIT_AS counted. File pages a
  command maps are not counted either, because the kernel can drop them. The cap is polled, so a
  command that allocates faster than the poll sees can go past it; the container's memory limit (or
  the host's memory) is the backstop for that, and with --memory-limit the command runs with the highest oom_score_adj, so
  the kernel's OOM killer takes it before the ACE process that started it.

It exits with the command's exit status (128 + N for a command killed by signal N). When it killed
the command itself, or could not start it, it says why on stderr and exits with a code that says
which: EXIT_SANDBOX_FAILURE when the command never ran, EXIT_DEADLINE, EXIT_PROCESS_LIMIT or
EXIT_MEMORY_LIMIT when it was killed for that, and EXIT_STOPPED when it was told to stop (EXIT_KILLED
when, with --term-grace, the stop ended in killing the command or what it left running).

A command can exit with any of those codes, and write any line on stderr, itself. So with
--status-fd=N, an fd the caller passes it, the launcher also writes its verdict there as one JSON
line, {"reason": ..., "exit_code": ...} and the values that go with the reason, whenever it ended
the command itself or could not run it; a command that exits on its own gets no line. The command
never inherits that fd, so only the launcher can write a verdict. runner.run_sandboxed() reads it.
"""

import ctypes
import json
import os
import signal
import sys
import time

# the same numbers on x86_64 and aarch64
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_RULE_NET_PORT = 2
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
_LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
_LANDLOCK_SCOPE_SIGNAL = 1 << 1
_PR_SET_CHILD_SUBREAPER = 36
_PR_SET_NO_NEW_PRIVS = 38

# the first Landlock ABI with TCP port rules (Linux 6.7)
NET_ABI = 4
# the first Landlock ABI with scopes (Linux 6.12)
SCOPE_ABI = 6

# the sandbox could not be set up or the command could not be started (the value timeout(1) uses)
EXIT_SANDBOX_FAILURE = 125
# the command ran past --deadline (the value timeout(1) uses)
EXIT_DEADLINE = 124
# the command had more than --max-processes live descendants
EXIT_PROCESS_LIMIT = 123
# the command's processes used more than --memory-limit bytes of memory
EXIT_MEMORY_LIMIT = 122
# the launcher was told to stop: what a command killed by SIGTERM exits with, which is what happened
EXIT_STOPPED = 128 + signal.SIGTERM
# told to stop with --term-grace, it had to kill the command or what the command left running: what
# docker reports for a container that outlived its stop_grace_period
EXIT_KILLED = 128 + signal.SIGKILL

# how often descendants are counted, and their memory measured, while the command runs; SIGCHLD also wakes the loop
_POLL_SECONDS = 0.05
# how long to keep killing descendants before giving up on stragglers
_KILL_SECONDS = 5

# the highest: the OOM killer takes this process, and so the command, before anything else in the container
_OOM_SCORE_ADJ_MAX = 1000

_STOP_SIGNALS = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
_WAKE_SIGNALS = {signal.SIGCHLD} | _STOP_SIGNALS


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    # packed in the kernel's uapi header; ctypes only packs with the "ms" layout, which with
    # _pack_ = 1 is the same 12 bytes with no padding
    _layout_ = "ms"
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _NetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _check(result: int) -> int:
    if result < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return result


def _syscall(number: int, *args: int) -> int:
    return _check(_libc.syscall(ctypes.c_long(number), *(ctypes.c_long(arg) for arg in args)))


def _prctl(option: int, value: int):
    _check(_libc.prctl(ctypes.c_int(option), ctypes.c_ulong(value), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)))


def set_child_subreaper(enabled: bool):
    """Have the orphans of this process's descendants reparented to it instead of to init, or stop adopting them."""
    _prctl(_PR_SET_CHILD_SUBREAPER, int(enabled))


def landlock_abi() -> int:
    """The kernel's Landlock ABI version, or 0 when Landlock is unavailable."""
    try:
        return _syscall(_SYS_LANDLOCK_CREATE_RULESET, 0, 0, _LANDLOCK_CREATE_RULESET_VERSION)
    except OSError:
        return 0


def restrict_self(abi: int, tcp_ports: list[int] | None):
    """Enter a Landlock domain limiting TCP connections to tcp_ports and, from ABI 6, scoping
    signals and abstract unix sockets to itself.

    tcp_ports None leaves TCP unrestricted. setpriv adds the filesystem rules as a nested domain
    after the exec, so this domain restricts no filesystem access. That takes one rule: REFER
    (renaming or linking a file into another directory) is denied by every Landlock domain unless a
    rule allows it, even one that does not handle it, so this domain allows it beneath / and leaves
    setpriv's domain, which allows it only in the working directory, to decide.
    """
    handled_net = 0 if tcp_ports is None else _LANDLOCK_ACCESS_NET_CONNECT_TCP
    scoped = (_LANDLOCK_SCOPE_SIGNAL | _LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET) if abi >= SCOPE_ABI else 0
    if not handled_net and not scoped:
        return

    # an older kernel accepts the full struct as long as the fields it does not know are zero
    attr = _RulesetAttr(_LANDLOCK_ACCESS_FS_REFER, handled_net, scoped)
    ruleset = _syscall(_SYS_LANDLOCK_CREATE_RULESET, ctypes.addressof(attr), ctypes.sizeof(attr), 0)
    try:
        root = os.open("/", os.O_PATH | os.O_CLOEXEC)
        try:
            rule = _PathBeneathAttr(_LANDLOCK_ACCESS_FS_REFER, root)
            _syscall(_SYS_LANDLOCK_ADD_RULE, ruleset, _LANDLOCK_RULE_PATH_BENEATH, ctypes.addressof(rule), 0)
        finally:
            os.close(root)

        for port in tcp_ports or []:
            rule = _NetPortAttr(_LANDLOCK_ACCESS_NET_CONNECT_TCP, port)
            _syscall(_SYS_LANDLOCK_ADD_RULE, ruleset, _LANDLOCK_RULE_NET_PORT, ctypes.addressof(rule), 0)

        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
        _syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0)
    finally:
        os.close(ruleset)


def descendants(pid: int) -> dict[int, bytes]:
    """Every descendant of pid (not pid itself), mapped to its /proc state letter."""
    children: dict[int, list[int]] = {}
    states: dict[int, bytes] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue

        try:
            with open(f"/proc/{entry}/stat", "rb") as fp:
                stat = fp.read()
        except OSError:
            # it exited while we looked
            continue

        # the command name is in parentheses and may contain anything, so parse after the last one
        fields = stat[stat.rindex(b")") + 2:].split()
        states[int(entry)] = fields[0]
        children.setdefault(int(fields[1]), []).append(int(entry))

    result: dict[int, bytes] = {}
    pending = list(children.get(pid, []))
    while pending:
        child = pending.pop()
        if child in result:
            continue

        result[child] = states[child]
        pending.extend(children.get(child, []))

    return result


def _live_descendants() -> list[int]:
    # a zombie (Z) or dead (X) process is already gone; it only waits to be reaped
    return [pid for pid, state in descendants(os.getpid()).items() if state not in (b"Z", b"X")]


def memory_used(pids: list[int]) -> int:
    """The bytes of memory pids use: their resident anonymous and shared memory (RssAnon and RssShmem),
    what the kernel cannot drop without swap, and their anonymous memory in swap (VmSwap), which leaves
    RssAnon exactly when memory is short. Reserved address space they never touched and file pages
    they map are not counted, and neither is swapped-out shared memory, which VmSwap leaves out."""
    total = 0
    for pid in pids:
        try:
            with open(f"/proc/{pid}/status", "rb") as fp:
                status = fp.read()
        except OSError:
            # it exited while we looked
            continue

        for line in status.splitlines():
            # in kB; a zombie, or a kernel thread, has none of them
            if line.startswith((b"RssAnon:", b"RssShmem:", b"VmSwap:")):
                total += int(line.split()[1]) * 1024

    return total


def raise_oom_score():
    """Make this process, and what it starts, the OOM killer's first choice. Raising it needs no privilege."""
    with open("/proc/self/oom_score_adj", "w") as fp:
        fp.write(str(_OOM_SCORE_ADJ_MAX))


# where the verdict goes (--status-fd); None without one
_status_fd: int | None = None


def _verdict(reason: str, exit_code: int, **details):
    """Write the launcher's verdict on --status-fd. Unbuffered, and a closed pipe is ignored, for the reasons _say gives."""
    if _status_fd is None:
        return

    try:
        os.write(_status_fd, (json.dumps({"reason": reason, "exit_code": exit_code, **details}) + "\n").encode())
    except OSError:
        pass  # nobody is reading any more


def _say(message: str):
    """Write a sandbox: line to stderr. Unbuffered, and a closed pipe is ignored: a reader that is gone
    (an API worker that died, which is what sent the SIGTERM) must not stop the cleanup, and a buffered
    line would fail again when the interpreter exits."""
    try:
        os.write(2, f"sandbox: {message}\n".encode(errors="replace"))
    except OSError:
        pass  # nobody is reading any more


def _signal(pid: int, signum: int):
    try:
        os.kill(pid, signum)
    except (ProcessLookupError, PermissionError):
        pass


def _reap(command_pid: int) -> int | None:
    """Reap every exited child; return the command's wait status if it was among them."""
    status = None
    while True:
        try:
            pid, wait_status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return status

        if pid == 0:
            return status

        if pid == command_pid:
            status = wait_status


def kill_descendants(command_pid: int) -> int:
    """Stop and kill every descendant, then reap them. Returns how many there were."""
    killed = set()
    give_up = time.monotonic() + _KILL_SECONDS
    while live := _live_descendants():
        killed.update(live)
        # stop them all first, so none can fork while the rest are being killed
        for pid in live:
            _signal(pid, signal.SIGSTOP)
        for pid in live:
            _signal(pid, signal.SIGKILL)

        _reap(command_pid)
        if time.monotonic() > give_up:
            _say(f"{len(live)} processes survived being killed")
            break

        time.sleep(0.01)

    _reap(command_pid)
    return len(killed)


def _exec_command(command: list[str], abi: int | None, tcp_ports: list[int] | None, signal_mask: set,
                  own_group: bool, oom_first: bool):
    """In the forked child: undo what the launcher changed, enter the Landlock domain (none when abi
    is None) and exec. With oom_first the command is the OOM killer's first choice, and the launcher,
    which has to clean up after it, is not."""
    try:
        if oom_first:
            raise_oom_score()
        if own_group:
            # so a graceful stop can SIGTERM the command and what stays in its group, but not the launcher
            os.setpgid(0, 0)
        signal.pthread_sigmask(signal.SIG_SETMASK, signal_mask)
        # python ignores these at startup and an exec keeps them ignored; the command gets the
        # defaults, so RLIMIT_FSIZE kills it and a closed pipe ends it
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
        if abi is not None:
            restrict_self(abi, tcp_ports)

        os.execv(command[0], command)
    except BaseException as e:
        try:
            _fail(f"cannot run {command[0]}: {e}")
        finally:
            os._exit(EXIT_SANDBOX_FAILURE)


def _group_running(pgid: int) -> bool:
    for pid in _live_descendants():
        try:
            if os.getpgid(pid) == pgid:
                return True
        except ProcessLookupError:
            pass  # it exited while we looked

    return False


def _terminate(command_pid: int, term_grace: float) -> bool:
    """SIGTERM the command's process group and wait up to term_grace seconds for the command, and the
    rest of the group the SIGTERM reached, to exit. False when the command did not."""
    try:
        os.killpg(command_pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return True  # the group is gone: nothing left to stop gracefully

    command_exited = False
    give_up = time.monotonic() + term_grace
    while (remaining := give_up - time.monotonic()) > 0:
        if _reap(command_pid) is not None:
            command_exited = True

        # what is still stopping is not killed for being slower than the command
        if command_exited and not _group_running(command_pid):
            return True

        # only SIGCHLD wakes this; a second stop signal waits in the queue (the abort is already under way)
        signal.sigtimedwait({signal.SIGCHLD}, min(_POLL_SECONDS, remaining))

    return command_exited


def _abort(command_pid: int, verdict: str, message: str, exit_code: int, term_grace: float = 0, **details) -> int:
    stopped = term_grace <= 0 or _terminate(command_pid, term_grace)
    # kill first, report after: the cleanup must not wait on a message
    killed = kill_descendants(command_pid)
    if not stopped:
        _say(f"the command did not stop within {term_grace:g} seconds of SIGTERM")
    elif term_grace > 0 and killed:
        _say(f"killed {killed} processes the command left running")
    _say(message)
    if term_grace > 0 and killed and exit_code == EXIT_STOPPED:
        exit_code = EXIT_KILLED
    _verdict(verdict, exit_code, **details)
    return exit_code


def supervise(command_pid: int, max_processes: int | None, deadline: float, term_grace: float = 0,
              memory_limit: int | None = None) -> int:
    """Wait for the command, enforcing the process cap, the memory cap and the deadline; return the exit code.

    With term_grace, a stop or the deadline gives the command that long to exit after SIGTERM before
    everything is killed. Going over the process cap or the memory cap kills at once."""
    while True:
        status = _reap(command_pid)
        if status is not None:
            # the command is done; whatever it left running is not
            kill_descendants(command_pid)
            code = os.waitstatus_to_exitcode(status)
            return 128 - code if code < 0 else code

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _abort(command_pid, "deadline", "the command ran past its deadline", EXIT_DEADLINE, term_grace)

        info = signal.sigtimedwait(_WAKE_SIGNALS, min(_POLL_SECONDS, remaining))
        if info is not None and info.si_signo in _STOP_SIGNALS:
            return _abort(command_pid, "stopped", "stopped", EXIT_STOPPED, term_grace)

        if max_processes is None and memory_limit is None:
            continue

        live = _live_descendants()
        if max_processes is not None and len(live) > max_processes:
            return _abort(command_pid, "process_limit", f"the command started more than {max_processes} processes",
                          EXIT_PROCESS_LIMIT, max_processes=max_processes)

        if memory_limit is not None and (used := memory_used(live)) > memory_limit:
            return _abort(command_pid, "memory_limit",
                          f"the command used {used} bytes of memory, more than its limit of {memory_limit} bytes",
                          EXIT_MEMORY_LIMIT, memory_used=used, memory_limit=memory_limit)


_USAGE = ("[--max-processes=N] [--memory-limit=BYTES] --deadline=SECONDS [--tcp-ports=PORT,...] "
          "[--term-grace=SECONDS] [--unconfined] [--status-fd=FD] -- command [args...]")


def _parse_arguments(argv: list[str]) -> tuple[int | None, int | None, float, list[int] | None, float, bool, list[str]]:
    """See _USAGE. Without --tcp-ports, TCP is unrestricted; `--tcp-ports=` (empty) allows no TCP
    connection.

    Parsed by hand: its callers (runner.py and aceapi_v2/cli/service.py) build the arguments, and
    argparse costs more to start than everything else the launcher does.
    """
    if "--" not in argv:
        raise ValueError("expected -- before the command")

    split = argv.index("--")
    options = dict(option.partition("=")[::2] for option in argv[:split])
    command = argv[split + 1:]
    if not command:
        raise ValueError("no command given")

    # --status-fd is _open_status_fd's, which runs first
    unknown = set(options) - {"--max-processes", "--memory-limit", "--deadline", "--tcp-ports", "--term-grace",
                              "--unconfined", "--status-fd"}
    if unknown:
        raise ValueError(f"unknown option(s) {sorted(unknown)}")

    tcp_ports = None
    if "--tcp-ports" in options:
        tcp_ports = [int(port) for port in options["--tcp-ports"].split(",") if port]

    unconfined = "--unconfined" in options
    if unconfined and tcp_ports is not None:
        raise ValueError("--tcp-ports needs the Landlock domain --unconfined skips")

    max_processes = int(options["--max-processes"]) if "--max-processes" in options else None
    memory_limit = int(options["--memory-limit"]) if "--memory-limit" in options else None
    return (max_processes, memory_limit, float(options["--deadline"]), tcp_ports, float(options.get("--term-grace", 0)),
            unconfined, command)


def _open_status_fd(argv: list[str]):
    """Take the --status-fd option, before the other options are parsed, so a usage error is reported
    there too. The fd is made non-inheritable, so the command never gets it."""
    global _status_fd
    options = argv[:argv.index("--")] if "--" in argv else argv
    for option in options:
        name, _, value = option.partition("=")
        if name == "--status-fd":
            fd = int(value)
            os.set_inheritable(fd, False)
            _status_fd = fd


def _fail(message: str) -> int:
    """The command cannot be run: say why and return EXIT_SANDBOX_FAILURE."""
    _say(message)
    _verdict("sandbox_failure", EXIT_SANDBOX_FAILURE, message=message)
    return EXIT_SANDBOX_FAILURE


def main(argv: list[str]) -> int:
    try:
        _open_status_fd(argv)
    except (ValueError, OSError) as e:
        _say(f"usage: {_USAGE} (--status-fd: {e})")
        return EXIT_SANDBOX_FAILURE

    try:
        max_processes, memory_limit, deadline_seconds, tcp_ports, term_grace, unconfined, command = _parse_arguments(argv)
    except (ValueError, KeyError) as e:
        return _fail(f"usage: {_USAGE} ({e})")

    try:
        set_child_subreaper(True)
    except OSError as e:
        return _fail(f"cannot become a child subreaper: {e}")

    abi = None if unconfined else landlock_abi()
    if tcp_ports is not None and abi < NET_ABI:
        return _fail(f"landlock ABI {abi} cannot restrict TCP ports (ABI {NET_ABI}, Linux 6.7, is needed)")

    deadline = time.monotonic() + deadline_seconds
    own_group = term_grace > 0

    # block the signals the supervisor waits for before forking, so none is missed
    signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _WAKE_SIGNALS)
    command_pid = os.fork()
    if command_pid == 0:
        _exec_command(command, abi, tcp_ports, signal_mask, own_group, oom_first=memory_limit is not None)

    if own_group:
        try:
            # also here, so the group exists before any SIGTERM to it, whichever of the two runs first
            os.setpgid(command_pid, command_pid)
        except OSError:
            pass  # the child has already exec'd, so its own setpgid already ran

    return supervise(command_pid, max_processes, deadline, term_grace, memory_limit)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
