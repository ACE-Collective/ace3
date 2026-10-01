"""The yara scanner server (docs/YARA_SCANNER.md).

    service process            YaraScannerServer: starts the manager, stops it
    └─ manager                 owns the listening socket, watches the rules, runs generations
       ├─ qa recorder          records the spooled matches of rules in QA mode (saq/yara_scanning/qa.py)
       ├─ generation G         compiles the rules once, forks the workers, restarts dead ones
       │  └─ worker × N        accept() on the shared listening socket, scan, spool QA matches
       └─ generation G+1       only while it is replacing G after a rule change

Every worker of every generation accepts on the same listening socket, so the kernel hands each
connection to a worker that is idle. The workers of a generation are forked after the rules are
compiled, so the compiled rules are compiled once and shared copy-on-write.

When the rules change the manager starts a new generation and retires the old one only once the
new one is ready. A ruleset that does not compile never replaces one that does. A retired worker
finishes the scan it is running and exits; connections still waiting in the socket's backlog are
picked up by the new generation's workers.

A worker never waits on the database. When a rule in QA mode matches a file the request says the
origin of, the worker hardlinks the file into the qa spool before it answers and writes the job
after, and the qa recorder records it from there. The recorder belongs to the manager, not to a
generation, so a rule change does not interrupt it.

Every level is stopped through a control pipe its parent holds the write end of: the parent writes
a byte and closes it, and a process whose parent dies sees EOF and stops too. The processes are
created with os.fork() by single-threaded parents, and every child closes the pipe ends that belong
to other processes right after the fork -- a stray copy of a write end would keep that pipe from
ever reading EOF when its owner dies.
"""

import logging
import multiprocessing.connection
import multiprocessing.util
import os
import select
import selectors
import signal
import socket
import time
from dataclasses import dataclass
from typing import Callable, Optional

import yara
from yara_scanner import YaraScanner

from saq.environment import ACE_MP_CONTEXT
from saq.error.reporting import log_loop_exception
from saq.yara_scanning import protocol
from saq.yara_scanning.qa import QASpooler, run_recorder

# how often the generation and manager loops look around when nothing happens
POLL_INTERVAL = 0.5

# the longest a crashing worker or generation waits before it is restarted
MAX_WORKER_RESTART_DELAY = 30
MAX_GENERATION_RESTART_DELAY = 60

# a worker that ran at least this long before it crashed is restarted without delay
WORKER_STABLE_SECONDS = 60


@dataclass(frozen=True)
class ScannerSettings:
    socket_dir: str
    signature_dir: str
    git_repo_dirs: tuple[str, ...]
    worker_count: int
    update_frequency: int
    default_timeout: int
    compile_timeout: int
    io_timeout: float
    max_data_bytes: int
    max_requests_per_worker: int
    backlog: int
    # where the workers spool the matches of rules in QA mode for the recorder. None runs no
    # recorder and spools nothing
    qa_spool_dir: Optional[str] = None
    # the most jobs the spool may hold before the workers drop new QA matches; 0 is no limit
    qa_spool_max_jobs: int = 0

    @property
    def socket_path(self) -> str:
        return os.path.join(self.socket_dir, protocol.SOCKET_NAME)

    @property
    def drain_timeout(self) -> float:
        """How long a retiring generation waits for its workers to finish the scans they are running."""
        return self.default_timeout + 1


def _close(fd: Optional[int]):
    if fd is None:
        return

    try:
        os.close(fd)
    except OSError:
        pass


def _signal_stop(ctl_w: Optional[int]):
    """Stops the process reading the other end of a control pipe. Closing the pipe is enough when
    this is the only copy of the write end; the byte also gets through when an unrelated fork of
    this process still holds one."""
    if ctl_w is None:
        return

    try:
        os.write(ctl_w, b"S")
    except OSError:
        pass  # the reader is already gone

    _close(ctl_w)


def _kill(pid: int, sig: int = signal.SIGKILL):
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass


def _reset_signals():
    """Drops the signal handlers inherited from the service process. They belong to ACE's
    shutdown coordinator, which does not exist below the service process; everything below it is
    stopped through its control pipe instead."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _fork(close_fds: list[Optional[int]], target: Callable[[], int]) -> int:
    """Forks a child that closes close_fds and runs target. Returns the pid of the child."""
    pid = os.fork()
    if pid != 0:
        return pid

    code = 1
    try:
        # a raw os.fork() skips the after-fork hooks multiprocessing runs in the children it
        # creates. without them this child would share its parent's connections to
        # multiprocessing managers (proxies), and two processes talking over one connection
        # read each other's replies and hang
        multiprocessing.util._run_after_forkers()

        _reset_signals()
        for fd in close_fds:
            _close(fd)

        code = target()
    except BaseException as e:
        logging.error("yara scanner process %d failed: %s", os.getpid(), e, exc_info=True)
    finally:
        os._exit(code)


def _reap() -> list[tuple[int, int]]:
    """Returns the (pid, exit code) of every child that exited, without blocking."""
    result = []
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return result

        if pid == 0:
            return result

        result.append((pid, os.waitstatus_to_exitcode(status)))


#
# worker
#

def _scan(scanner: YaraScanner, settings: ScannerSettings, request: dict, data: Optional[bytes]) -> dict:
    timeout = request.get("timeout") or settings.default_timeout
    ext_vars = request.get("ext_vars") or {}
    meta_tags = request.get("meta_tags")

    try:
        if request["op"] == protocol.OP_SCAN_FILE:
            matched = scanner.scan(request["path"], external_vars=ext_vars, timeout=timeout, meta_tags=meta_tags)
        else:
            matched = scanner.scan_data(data, external_vars=ext_vars, timeout=timeout, meta_tags=meta_tags)

    except yara.TimeoutError as e:
        return {"status": protocol.STATUS_TIMEOUT, "error": {"type": type(e).__name__, "message": str(e)}}

    except Exception as e:
        logging.warning("yara scan of %s failed: %s", request.get("path") or "data stream", e)
        return {"status": protocol.STATUS_ERROR, "error": {"type": type(e).__name__, "message": str(e)}}

    matches = scanner.scan_results if matched else []
    return {"status": protocol.STATUS_OK, "matches": protocol.encode_matches(matches)}


def _serve_connection(conn: socket.socket, scanner: YaraScanner, settings: ScannerSettings, spooler: Optional[QASpooler]):
    # a connection accepted from a non-blocking listener comes back blocking; without a timeout
    # a client that stalls would hold this worker forever
    conn.settimeout(settings.io_timeout)

    try:
        conn.sendall(protocol.ACK)
        request = protocol.recv_json(conn, protocol.MAX_REQUEST_BYTES)

        error = protocol.validate_request(request)
        if error:
            logging.warning("invalid yara scan request: %s", error)
            protocol.send_json(conn, {"status": protocol.STATUS_BAD_REQUEST, "error": {"type": "BadRequest", "message": error}})
            return

        data = None
        if request["op"] == protocol.OP_SCAN_DATA:
            data = protocol.recv_frame(conn, settings.max_data_bytes)

        response = _scan(scanner, settings, request, data)

        # the scanned file is pinned before the client has its answer and may delete it; the job is
        # written after, so writing it costs the client nothing
        job = spooler.begin(request, response) if spooler else None
        try:
            protocol.send_json(conn, response)
        finally:
            if job:
                spooler.commit(job)

    except (OSError, protocol.ProtocolError) as e:
        # the client went away or does not speak the protocol: there is nobody to answer
        logging.warning("yara scanner connection failed: %s", e)


def _run_worker(settings: ScannerSettings, scanner: YaraScanner, listen_sock: socket.socket, ctl_r: int) -> int:
    selector = selectors.DefaultSelector()
    selector.register(ctl_r, selectors.EVENT_READ)
    selector.register(listen_sock, selectors.EVENT_READ)

    spooler = QASpooler(settings.qa_spool_dir, settings.qa_spool_max_jobs) if settings.qa_spool_dir else None

    handled = 0
    while True:
        ready = {key.fileobj for key, _ in selector.select()}

        # the control pipe is readable once the generation wrote to it, closed it, or died, and
        # then this worker stops taking connections
        if ctl_r in ready:
            return 0

        try:
            conn, _ = listen_sock.accept()
        except (BlockingIOError, InterruptedError, ConnectionAbortedError):
            # every idle worker is woken for each connection and only one of them gets it
            continue

        with conn:
            _serve_connection(conn, scanner, settings, spooler)

        handled += 1
        if settings.max_requests_per_worker and handled >= settings.max_requests_per_worker:
            logging.info("yara scanner worker %d recycling after %d requests", os.getpid(), handled)
            return 0


#
# generation
#

class _Generation:
    """Runs in the generation process: compiles the rules, then keeps worker_count workers alive
    until the manager closes the control pipe."""

    def __init__(self, settings: ScannerSettings, generation_id: int, listen_sock: socket.socket, ctl_r: int, ready_w: int):
        self.settings = settings
        self.generation_id = generation_id
        self.listen_sock = listen_sock
        self.ctl_r = ctl_r
        self.ready_w: Optional[int] = ready_w
        self.scanner: Optional[YaraScanner] = None

        # the workers hold the read end; closing the write end stops them
        self.worker_ctl_r: Optional[int] = None
        self.worker_ctl_w: Optional[int] = None

        self.workers: dict[int, int] = {}  # pid -> slot
        self.worker_started: dict[int, float] = {}  # slot -> when
        self.worker_crashes: dict[int, int] = {}  # slot -> consecutive crashes
        self.restart_at: dict[int, float] = {}  # slot -> when

    def _report(self, message: bytes):
        os.write(self.ready_w, message)
        _close(self.ready_w)
        self.ready_w = None

    def run(self) -> int:
        start = time.monotonic()
        try:
            self.scanner = YaraScanner(
                signature_dir=self.settings.signature_dir,
                git_repo_dirs=list(self.settings.git_repo_dirs),
                default_timeout=self.settings.default_timeout)

            # a rule file that does not compile is logged and left out; the rest are loaded
            self.scanner.load_rules()
        except Exception as e:
            self._report(b"E" + str(e).encode(errors="replace")[:4096])
            return 1

        if self.scanner.rules is None:
            self._report(b"Eno yara rules could be loaded")
            return 1

        logging.info("yara scanner generation %d compiled its rules in %.1f seconds",
                     self.generation_id, time.monotonic() - start)

        self.worker_ctl_r, self.worker_ctl_w = os.pipe()
        for slot in range(self.settings.worker_count):
            self._start_worker(slot)

        self._report(b"R")

        while True:
            # the control pipe is readable once the manager wrote to it, closed it, or died
            readable, _, _ = select.select([self.ctl_r], [], [], POLL_INTERVAL)
            if readable:
                break

            self._reap_workers()
            now = time.monotonic()
            for slot, when in list(self.restart_at.items()):
                if now >= when:
                    del self.restart_at[slot]
                    self._start_worker(slot)

        return self._retire()

    def _start_worker(self, slot: int):
        settings, scanner, listen_sock, worker_ctl_r = self.settings, self.scanner, self.listen_sock, self.worker_ctl_r
        pid = _fork([self.ctl_r, self.ready_w, self.worker_ctl_w],
                    lambda: _run_worker(settings, scanner, listen_sock, worker_ctl_r))
        self.workers[pid] = slot
        self.worker_started[slot] = time.monotonic()

    def _reap_workers(self):
        for pid, code in _reap():
            slot = self.workers.pop(pid, None)
            if slot is None:
                continue

            if code == 0:
                # recycled after max_requests_per_worker
                self.worker_crashes[slot] = 0
                self.restart_at[slot] = time.monotonic()
                continue

            if time.monotonic() - self.worker_started[slot] >= WORKER_STABLE_SECONDS:
                self.worker_crashes[slot] = 0

            self.worker_crashes[slot] = self.worker_crashes.get(slot, 0) + 1
            delay = min(2 ** (self.worker_crashes[slot] - 1), MAX_WORKER_RESTART_DELAY)
            logging.error("yara scanner worker %d of generation %d exited with %d; restarting it in %d seconds",
                          pid, self.generation_id, code, delay)
            self.restart_at[slot] = time.monotonic() + delay

    def _retire(self) -> int:
        logging.info("yara scanner generation %d retiring", self.generation_id)
        _signal_stop(self.worker_ctl_w)
        self.worker_ctl_w = None

        # the workers finish the scan they are running, which the yara timeout bounds
        deadline = time.monotonic() + self.settings.drain_timeout
        while self.workers and time.monotonic() < deadline:
            for pid, _ in _reap():
                self.workers.pop(pid, None)

            time.sleep(0.05)

        for pid in self.workers:
            logging.warning("yara scanner worker %d did not stop in time: killing it", pid)
            _kill(pid)

        return 0


#
# manager
#

@dataclass
class _GenerationHandle:
    generation_id: int
    pid: int
    ctl_w: Optional[int]
    ready_r: Optional[int]
    started: float
    retired: Optional[float] = None


@dataclass
class _RecorderHandle:
    pid: int
    ctl_w: Optional[int]
    started: float


class _Manager:
    """Runs in the manager process."""

    def __init__(self, settings: ScannerSettings, ctl_r: int, status_w: int):
        self.settings = settings
        self.ctl_r = ctl_r
        self.status_w: Optional[int] = status_w

        self.listen_sock: Optional[socket.socket] = None
        # the socket is bound under a private name, and published under the name clients use
        # (a symlink) only while a generation is serving it
        self.bound_path = f"{settings.socket_path}.{os.getpid()}"
        self.published = False

        # watches the rule sources without ever compiling them
        self.tracker: Optional[YaraScanner] = None

        self.next_generation_id = 1
        self.current: Optional[_GenerationHandle] = None
        self.pending: Optional[_GenerationHandle] = None
        self.retiring: dict[int, _GenerationHandle] = {}

        # consecutive failures to get a generation serving while none is
        self.failures = 0
        self.retry_at: Optional[float] = None

        # the qa recorder, while it runs; it is restarted at recorder_restart_at after it died
        self.recorder: Optional[_RecorderHandle] = None
        self.recorder_failures = 0
        self.recorder_restart_at: Optional[float] = None

    def run(self) -> int:
        _reset_signals()

        # forked before anything else exists, so it inherits as little as possible
        if self.settings.qa_spool_dir:
            os.makedirs(self.settings.qa_spool_dir, exist_ok=True)
            self._start_recorder()

        self._bind()
        self.tracker = YaraScanner(signature_dir=self.settings.signature_dir, git_repo_dirs=list(self.settings.git_repo_dirs))
        self._start_generation()
        next_rules_check = time.monotonic() + self.settings.update_frequency

        while True:
            try:
                fds = [self.ctl_r]
                if self.pending:
                    fds.append(self.pending.ready_r)

                readable, _, _ = select.select(fds, [], [], POLL_INTERVAL)

                # the control pipe is readable once the service wrote to it, closed it, or died
                if self.ctl_r in readable:
                    break

                if self.pending and self.pending.ready_r in readable:
                    self._read_ready()

                self._reap_children()
                now = time.monotonic()

                if self.pending and now - self.pending.started >= self.settings.compile_timeout:
                    self._fail_pending(f"not ready after {self.settings.compile_timeout} seconds")

                if now >= next_rules_check:
                    next_rules_check = now + self.settings.update_frequency
                    if self.tracker.rules_changed():
                        logging.info("yara rules changed: starting a new yara scanner generation")
                        if self.pending:
                            self._discard_pending()

                        self._start_generation()

                if not self.current and not self.pending and self.retry_at is not None and now >= self.retry_at:
                    self._start_generation()

                if not self.recorder and self.recorder_restart_at is not None and now >= self.recorder_restart_at:
                    self._start_recorder()

            except Exception as e:
                log_loop_exception(e, "managing yara scanner generations")
                time.sleep(1)

        self._shutdown()
        return 0

    def _bind(self):
        os.makedirs(self.settings.socket_dir, exist_ok=True)
        self._remove_stale_sockets()

        self.listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listen_sock.bind(self.bound_path)
        self.listen_sock.listen(self.settings.backlog)
        # shared by every worker; see _run_worker
        self.listen_sock.setblocking(False)

    def _remove_stale_sockets(self):
        """Removes the sockets that managers which are no longer running left behind."""
        prefix = f"{protocol.SOCKET_NAME}."
        for name in os.listdir(self.settings.socket_dir):
            if not name.startswith(prefix):
                continue

            path = os.path.join(self.settings.socket_dir, name)
            suffix = name[len(prefix):]
            if suffix.isdigit() and int(suffix) != os.getpid():
                try:
                    os.kill(int(suffix), 0)
                    continue  # still running
                except ProcessLookupError:
                    pass
                except PermissionError:
                    continue

            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def _publish(self):
        if self.published:
            return

        # replace whatever is there in one step
        temp_path = f"{self.settings.socket_path}.link.{os.getpid()}"
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass

        os.symlink(os.path.basename(self.bound_path), temp_path)
        os.replace(temp_path, self.settings.socket_path)
        self.published = True

    def _unpublish(self):
        """Takes the socket away from clients, so they fail at once and fall back instead of waiting
        on a socket nothing serves."""
        if not self.published:
            return

        self.published = False
        try:
            if os.readlink(self.settings.socket_path) == os.path.basename(self.bound_path):
                os.unlink(self.settings.socket_path)
        except (FileNotFoundError, OSError):
            pass

    def _owned_fds(self) -> list[Optional[int]]:
        result: list[Optional[int]] = [self.ctl_r, self.status_w]
        for handle in [self.current, self.pending, *self.retiring.values()]:
            if handle:
                result.extend([handle.ctl_w, handle.ready_r])

        if self.recorder:
            result.append(self.recorder.ctl_w)

        return result

    def _start_recorder(self):
        ctl_r, ctl_w = os.pipe()
        spool_dir, listen_sock = self.settings.qa_spool_dir, self.listen_sock

        def _recorder() -> int:
            # a restarted recorder is forked after the socket is bound. a copy of it would keep
            # accepting connections nothing answers if the manager were killed
            if listen_sock:
                listen_sock.close()

            return run_recorder(spool_dir, ctl_r)

        pid = _fork(self._owned_fds() + [ctl_w], _recorder)
        _close(ctl_r)
        self.recorder = _RecorderHandle(pid, ctl_w, time.monotonic())
        self.recorder_restart_at = None
        logging.info("started yara qa recorder (pid %d)", pid)

    def _recorder_exited(self, code: int):
        """The recorder only stops on its own when it is told to, so this is a crash."""
        handle, self.recorder = self.recorder, None
        _close(handle.ctl_w)

        if time.monotonic() - handle.started >= WORKER_STABLE_SECONDS:
            self.recorder_failures = 0

        delay = min(2 ** self.recorder_failures, MAX_GENERATION_RESTART_DELAY)
        self.recorder_failures += 1
        self.recorder_restart_at = time.monotonic() + delay
        logging.error("yara qa recorder %d exited with %d; restarting it in %d seconds", handle.pid, code, delay)

    def _start_generation(self):
        generation_id = self.next_generation_id
        self.next_generation_id += 1
        self.retry_at = None

        ctl_r, ctl_w = os.pipe()
        ready_r, ready_w = os.pipe()

        settings, listen_sock = self.settings, self.listen_sock
        pid = _fork(self._owned_fds() + [ctl_w, ready_r],
                    lambda: _Generation(settings, generation_id, listen_sock, ctl_r, ready_w).run())

        _close(ctl_r)
        _close(ready_w)
        self.pending = _GenerationHandle(generation_id, pid, ctl_w, ready_r, time.monotonic())
        logging.info("started yara scanner generation %d (pid %d)", generation_id, pid)

    def _read_ready(self):
        """Reads what the pending generation reported: ready, an error, or nothing because it died."""
        try:
            message = os.read(self.pending.ready_r, 4096)
        except OSError as e:
            message = b"E" + str(e).encode()

        if message.startswith(b"R"):
            self._promote()
        elif message.startswith(b"E"):
            self._fail_pending(message[1:].decode(errors="replace"))
        else:
            self._fail_pending("exited before it was ready")

    def _promote(self):
        handle, self.pending = self.pending, None
        _close(handle.ready_r)
        handle.ready_r = None

        previous, self.current = self.current, handle
        if previous:
            self._retire(previous)

        self._publish()
        self.failures = 0
        logging.info("yara scanner generation %d is serving with %d workers", handle.generation_id, self.settings.worker_count)

        if self.status_w is not None:
            try:
                os.write(self.status_w, b"R")
            except OSError:
                pass  # nobody is waiting for it any more

            _close(self.status_w)
            self.status_w = None

    def _discard(self, handle: _GenerationHandle):
        _signal_stop(handle.ctl_w)
        _close(handle.ready_r)
        handle.ctl_w = handle.ready_r = None
        _kill(handle.pid)

    def _discard_pending(self):
        """A rule change while a generation is still compiling makes it stale."""
        logging.info("discarding yara scanner generation %d: the rules changed while it was compiling", self.pending.generation_id)
        self._discard(self.pending)
        self.pending = None

    def _fail_pending(self, reason: str):
        handle, self.pending = self.pending, None
        self._discard(handle)

        if self.current:
            logging.error("yara scanner generation %d failed to start: %s -- generation %d keeps serving the "
                          "previous rules until the rules change again", handle.generation_id, reason, self.current.generation_id)
        else:
            logging.error("yara scanner generation %d failed to start: %s", handle.generation_id, reason)
            self._schedule_retry()

    def _schedule_retry(self):
        delay = min(2 ** self.failures, MAX_GENERATION_RESTART_DELAY)
        self.failures += 1
        self.retry_at = time.monotonic() + delay
        logging.warning("no yara scanner generation is serving: retrying in %d seconds", delay)

    def _retire(self, handle: _GenerationHandle):
        _signal_stop(handle.ctl_w)
        handle.ctl_w = None
        handle.retired = time.monotonic()
        self.retiring[handle.pid] = handle

    def _reap_children(self):
        for pid, code in _reap():
            if self.recorder and pid == self.recorder.pid:
                self._recorder_exited(code)
                continue

            if self.pending and pid == self.pending.pid:
                # whatever it reported before it exited is still in the pipe
                self._read_ready()

            if self.current and pid == self.current.pid:
                logging.error("yara scanner generation %d exited unexpectedly with %d", self.current.generation_id, code)
                _close(self.current.ctl_w)
                self.current = None
                self._unpublish()
                self._schedule_retry()

            self.retiring.pop(pid, None)

        # a generation gets drain_timeout to retire; give it a little more before killing it
        now = time.monotonic()
        for handle in self.retiring.values():
            if now - handle.retired > self.settings.drain_timeout + 5:
                logging.warning("yara scanner generation %d did not retire in time: killing it", handle.generation_id)
                _kill(handle.pid)

    def _shutdown(self):
        logging.info("yara scanner manager stopping")
        self._unpublish()

        # stopped first: it may be in the middle of storing a file. whatever it has not recorded
        # stays in the spool for the next start
        if self.recorder:
            _signal_stop(self.recorder.ctl_w)
            self.recorder.ctl_w = None

        if self.pending:
            self._discard(self.pending)
            self.retiring[self.pending.pid] = self.pending
            self.pending = None

        if self.current:
            self._retire(self.current)
            self.current = None

        deadline = time.monotonic() + self.settings.drain_timeout + 1
        while (self.retiring or self.recorder) and time.monotonic() < deadline:
            for pid, _ in _reap():
                self.retiring.pop(pid, None)
                if self.recorder and pid == self.recorder.pid:
                    self.recorder = None

            time.sleep(0.05)

        for handle in self.retiring.values():
            logging.warning("yara scanner generation %d did not stop in time: killing it", handle.generation_id)
            _kill(handle.pid)

        if self.recorder:
            logging.warning("yara qa recorder %d did not stop in time: killing it", self.recorder.pid)
            _kill(self.recorder.pid)

        self.listen_sock.close()
        try:
            os.unlink(self.bound_path)
        except FileNotFoundError:
            pass


def _run_manager(settings: ScannerSettings, ctl_r: int, status_w: int, parent_fds: list[int]):
    for fd in parent_fds:
        _close(fd)

    # the manager and everything below it form one process group, so the service can kill
    # whatever is left of it in one call
    os.setpgid(0, 0)
    _Manager(settings, ctl_r, status_w).run()


class YaraScannerServer:
    """Runs in the service process: starts and stops the manager."""

    def __init__(self, settings: ScannerSettings):
        self.settings = settings
        self.process: Optional[multiprocessing.Process] = None
        self.ctl_w: Optional[int] = None
        self.status_r: Optional[int] = None
        self.ready = False

    def start(self):
        ctl_r, self.ctl_w = os.pipe()
        self.status_r, status_w = os.pipe()

        self.process = ACE_MP_CONTEXT.Process(
            target=_run_manager,
            args=(self.settings, ctl_r, status_w, [self.ctl_w, self.status_r]),
            name="yara scanner manager")
        self.process.start()

        _close(ctl_r)
        _close(status_w)

        # also set from here so the group exists before anything tries to kill it
        try:
            os.setpgid(self.process.pid, self.process.pid)
        except OSError:
            pass

        logging.info("started yara scanner manager (pid %d)", self.process.pid)

    def wait_for_start(self, timeout: float) -> bool:
        """Returns True once the first generation is serving, False if that does not happen within timeout."""
        if self.ready:
            return True

        if self.status_r is None or self.process is None:
            return False

        readable = multiprocessing.connection.wait([self.status_r, self.process.sentinel], timeout)
        if self.status_r in readable:
            message = os.read(self.status_r, 1)
            _close(self.status_r)
            self.status_r = None
            self.ready = message == b"R"

        return self.ready

    def stop(self, timeout: Optional[float] = None):
        """Stops the manager, waiting up to timeout for it, then kills whatever is left."""
        _signal_stop(self.ctl_w)
        self.ctl_w = None
        _close(self.status_r)
        self.status_r = None

        if self.process is None:
            return

        if timeout is None:
            timeout = self.settings.drain_timeout + 3

        self.process.join(timeout)
        if self.process.is_alive():
            logging.warning("yara scanner manager did not stop in time: killing it")

        # stragglers, or the whole tree if the manager did not stop
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

        self.process.join(1)

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Waits for the manager to exit. Returns True if it did."""
        if self.process is None:
            return True

        return bool(multiprocessing.connection.wait([self.process.sentinel], timeout))
