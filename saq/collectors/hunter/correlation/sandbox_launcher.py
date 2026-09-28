"""Supervises one sandboxed correlate command. sandbox.py starts this instead of the command.

It runs as a script, with the venv's python in isolated mode, so it uses the standard library only:

    python3 -I -S sandbox_launcher.py --max-processes=64 --deadline=330 --tcp-ports=443,53 -- prlimit ... -- setpriv ... -- command

Before the exec, the child enters a Landlock domain for what setpriv cannot express (setpriv then
nests its filesystem rules inside it):

- TCP ports. With --tcp-ports, the command can open a TCP connection only to those ports
  (Landlock ABI 4, Linux 6.7). That keeps it off the cloud metadata endpoint (port 80), whose
  instance credentials would undo the rest of the sandbox, and off ACE's own services. UDP, and so
  ordinary DNS, is not affected. On a kernel that cannot enforce it the command is not run.
- Signal scoping. Nothing the command starts can signal, or connect to an abstract unix socket
  of, a process outside the domain (Landlock ABI 6, Linux 6.12): not the ACE process that ran the
  hunt, not the other API workers, not this launcher. On an older kernel the scope is skipped, and
  prepare_sandbox() logs that at startup.

The domain restricts no filesystem access; restrict_self() says why it still needs one filesystem rule.

The launcher itself forks the command and stays outside that domain, which is what lets it do two
things the command cannot undo:

- Cleanup. It is a child subreaper, so whatever the command starts is reparented to it instead of
  to the container's init, even a process that left the session. When the command exits, when
  ACE sends SIGTERM (timeout, too much output), or at --deadline, every descendant is stopped and
  killed.
- A process cap. A command with more than --max-processes live descendants is killed.

It exits with the command's exit status (128 + N for a command killed by signal N). When it killed
the command itself, or could not start it, it says why on stderr and exits EXIT_SANDBOX_FAILURE.
"""

import ctypes
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

# the launcher's own failure, or its verdict when it killed the command (the value timeout(1) uses)
EXIT_SANDBOX_FAILURE = 125

# how often descendants are counted while the command runs; SIGCHLD also wakes the loop
_POLL_SECONDS = 0.05
# how long to keep killing descendants before giving up on stragglers
_KILL_SECONDS = 5

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


def kill_descendants(command_pid: int):
    """Stop and kill every descendant, then reap them."""
    give_up = time.monotonic() + _KILL_SECONDS
    while live := _live_descendants():
        # stop them all first, so none can fork while the rest are being killed
        for pid in live:
            _signal(pid, signal.SIGSTOP)
        for pid in live:
            _signal(pid, signal.SIGKILL)

        _reap(command_pid)
        if time.monotonic() > give_up:
            print(f"sandbox: {len(live)} processes survived being killed", file=sys.stderr)
            break

        time.sleep(0.01)

    _reap(command_pid)


def _exec_command(command: list[str], abi: int, tcp_ports: list[int] | None, signal_mask: set):
    """In the forked child: undo what the launcher changed, enter the Landlock domain and exec."""
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, signal_mask)
        # python ignores these at startup and an exec keeps them ignored; the command gets the
        # defaults, so RLIMIT_FSIZE kills it and a closed pipe ends it
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
        restrict_self(abi, tcp_ports)

        os.execv(command[0], command)
    except BaseException as e:
        try:
            os.write(2, f"sandbox: cannot run {command[0]}: {e}\n".encode(errors="replace"))
        finally:
            os._exit(EXIT_SANDBOX_FAILURE)


def _abort(command_pid: int, reason: str) -> int:
    kill_descendants(command_pid)
    print(f"sandbox: {reason}", file=sys.stderr)
    return EXIT_SANDBOX_FAILURE


def supervise(command_pid: int, max_processes: int, deadline: float) -> int:
    """Wait for the command, enforcing the process cap and the deadline; return the exit code."""
    while True:
        status = _reap(command_pid)
        if status is not None:
            # the command is done; whatever it left running is not
            kill_descendants(command_pid)
            code = os.waitstatus_to_exitcode(status)
            return 128 - code if code < 0 else code

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _abort(command_pid, "the command ran past its deadline")

        info = signal.sigtimedwait(_WAKE_SIGNALS, min(_POLL_SECONDS, remaining))
        if info is not None and info.si_signo in _STOP_SIGNALS:
            return _abort(command_pid, "stopped")

        if len(_live_descendants()) > max_processes:
            return _abort(command_pid, f"the command started more than {max_processes} processes")


def _parse_arguments(argv: list[str]) -> tuple[int, float, list[int] | None, list[str]]:
    """--max-processes=N --deadline=SECONDS [--tcp-ports=PORT,...] -- command [args...]

    Without --tcp-ports, TCP is unrestricted; `--tcp-ports=` (empty) allows no TCP connection.

    Parsed by hand: sandbox.py is the only caller, and argparse costs more to start than
    everything else the launcher does.
    """
    if "--" not in argv:
        raise ValueError("expected -- before the command")

    split = argv.index("--")
    options = dict(option.split("=", 1) for option in argv[:split])
    command = argv[split + 1:]
    if not command:
        raise ValueError("no command given")

    tcp_ports = None
    if "--tcp-ports" in options:
        tcp_ports = [int(port) for port in options["--tcp-ports"].split(",") if port]

    return int(options["--max-processes"]), float(options["--deadline"]), tcp_ports, command


def main(argv: list[str]) -> int:
    try:
        max_processes, deadline_seconds, tcp_ports, command = _parse_arguments(argv)
    except (ValueError, KeyError) as e:
        print(f"sandbox: usage: --max-processes=N --deadline=SECONDS [--tcp-ports=PORT,...] -- command [args...] ({e})", file=sys.stderr)
        return EXIT_SANDBOX_FAILURE

    try:
        _prctl(_PR_SET_CHILD_SUBREAPER, 1)
    except OSError as e:
        print(f"sandbox: cannot become a child subreaper: {e}", file=sys.stderr)
        return EXIT_SANDBOX_FAILURE

    abi = landlock_abi()
    if tcp_ports is not None and abi < NET_ABI:
        print(f"sandbox: landlock ABI {abi} cannot restrict TCP ports (ABI {NET_ABI}, Linux 6.7, is needed)", file=sys.stderr)
        return EXIT_SANDBOX_FAILURE

    deadline = time.monotonic() + deadline_seconds

    # block the signals the supervisor waits for before forking, so none is missed
    signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _WAKE_SIGNALS)
    command_pid = os.fork()
    if command_pid == 0:
        _exec_command(command, abi, tcp_ports, signal_mask)

    return supervise(command_pid, max_processes, deadline)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
