"""The tool runner: runs the sandboxed tools of every ACE process on the node, each in a cgroup of its
own (docs/TOOL_SANDBOX.md).

One thread accepts connections on a unix socket and one thread per connection runs its command in
the Landlock sandbox (saq/sandbox/runner.py), under a new cgroup whose memory.max is the command's
memory limit. A run starts only once the memory limits of the runs in progress, its own included,
fit in the container's memory; until then it waits, and the wait comes out of its timeout.
"""

import datetime
import logging
import os
import select
import socket
import threading
import time
from typing import Optional

from saq.configuration.schema import SandboxConfig
from saq.sandbox.launcher import NET_ABI, SCOPE_ABI, landlock_abi
from saq.sandbox.runner import (
    LAUNCHER_STOP_SECONDS,
    SandboxCancelled,
    SandboxOutputExceeded,
    SandboxResult,
    build_sandbox_argv,
    landlock_available,
    run_sandboxed,
)
from saq.tool_runner import protocol
from saq.tool_runner.cgroup import RunCgroups, memory_budget
from saq.yara_scanning.protocol import ProtocolError, recv_json, send_json

# how often the accept loop checks whether it was told to stop, and a run waiting for memory
# whether it was cancelled
_POLL_SECONDS = 0.5

# a run whose wait for memory leaves it less time than this is not started
_MIN_RUN_SECONDS = 1.0

# how long stop() gives the runs to be stopped and answered: a run notices within _POLL_SECONDS,
# the launcher gets LAUNCHER_STOP_SECONDS, removing the cgroup up to 5 more
STOP_SECONDS = _POLL_SECONDS + LAUNCHER_STOP_SECONDS + 5 + 2

_BACKLOG = 128


def _client_gone(conn: socket.socket) -> bool:
    """Whether the client shut down its side of the connection (or closed it)."""
    # select rather than MSG_DONTWAIT: the socket has a timeout, and Python waits that long for a recv
    # before it tries one
    readable, _, _ = select.select([conn], [], [], 0)
    if not readable:
        return False

    try:
        return conn.recv(1, socket.MSG_PEEK) == b""
    except OSError:
        return True


def _result_fields(result: SandboxResult) -> dict:
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


class ToolRunnerServer:

    def __init__(self, socket_path: str, io_timeout: float, cgroups: Optional[RunCgroups] = None,
                 budget: Optional[int] = None):
        self.socket_path = socket_path
        self.io_timeout = io_timeout
        self.cgroups = cgroups
        self.budget = budget
        self._listener: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._handlers: set[threading.Thread] = set()
        self._handlers_lock = threading.Lock()
        self._stopping = threading.Event()
        self._started = threading.Event()
        # the memory limits of the runs in progress, and the runs waiting for some
        self._memory = threading.Condition()
        self._reserved = 0

    def start(self):
        """Checks this container can run sandboxed tools in cgroups and starts serving. Raises when it
        cannot, so a runner that would bound nothing never serves."""
        if not landlock_available():
            raise RuntimeError("landlock is unavailable here, so no sandboxed tool can run")

        abi = landlock_abi()
        if abi < NET_ABI:
            logging.error("landlock ABI %s cannot restrict TCP ports (ABI %s, Linux 6.7, is needed): every tool with "
                          "allowed_tcp_ports other than null fails", abi, NET_ABI)
        if abi < SCOPE_ABI:
            logging.warning("landlock ABI %s cannot scope signals (ABI %s, Linux 6.12, is needed): a sandboxed tool "
                            "can signal other processes running as this user", abi, SCOPE_ABI)

        if self.cgroups is None:
            self.cgroups = RunCgroups.delegated()
        self.cgroups.sweep()
        if self.budget is None:
            self.budget = memory_budget()

        os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)
        try:
            # a socket left by a runner that died: nothing serves it
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass  # none was left

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.socket_path)
        listener.listen(_BACKLOG)
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, name="tool-runner", daemon=True)
        self._thread.start()
        self._started.set()
        logging.info("tool runner serving %s: runs in cgroups under %s, %d bytes of memory for them, landlock ABI %s",
                     self.socket_path, self.cgroups.parent, self.budget, abi)

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self._started.wait(timeout)

    def stop(self):
        """Stops accepting, and stops every run in progress; each is answered with STATUS_STOPPED."""
        self._stopping.set()
        with self._memory:
            self._memory.notify_all()

    def wait_until_stopped(self):
        """Waits for stop(), or for the accept loop to die, and then for the runs to finish, at most
        STOP_SECONDS more. ace service start waits here while the service runs, and bounds the call once
        it has called stop()."""
        while not self._stopping.wait(_POLL_SECONDS):
            if self._thread is None or not self._thread.is_alive():
                break

        give_up = time.monotonic() + STOP_SECONDS
        if self._thread is not None:
            self._thread.join(max(0, give_up - time.monotonic()))

        with self._handlers_lock:
            handlers = list(self._handlers)
        for handler in handlers:
            handler.join(max(0, give_up - time.monotonic()))
            if handler.is_alive():
                logging.warning("a tool run did not stop within %d seconds of the tool runner stopping", STOP_SECONDS)

    def _serve(self):
        # stop() is what ends this loop rather than is_shutting_down(): ace service start calls it on a
        # signal, and the test suite runs this server in its own process, where a test that requests a
        # shutdown must not stop the runner every later test uses
        try:
            while not self._stopping.is_set():
                try:
                    readable, _, _ = select.select([self._listener], [], [], _POLL_SECONDS)
                    if not readable:
                        continue

                    conn, _ = self._listener.accept()
                except OSError as e:
                    logging.error("tool runner unable to accept a connection on %s: %s", self.socket_path, e, exc_info=e)
                    time.sleep(_POLL_SECONDS)
                    continue

                handler = threading.Thread(target=self._handle, args=(conn,), name="tool-run", daemon=True)
                with self._handlers_lock:
                    self._handlers.add(handler)
                handler.start()
        finally:
            self._listener.close()
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass  # already gone, or another runner's by now

    def _handle(self, conn: socket.socket):
        try:
            with conn:
                response = self._run(conn)
                try:
                    send_json(conn, response)
                except OSError as e:
                    # a client that gave up on the answer, or died
                    logging.info("tool runner could not answer a run of %s: %s", response.get("tool"), e)
        except Exception as e:
            logging.exception("tool runner failed to handle a request: %s", e)
        finally:
            with self._handlers_lock:
                self._handlers.discard(threading.current_thread())

    def _run(self, conn: socket.socket) -> dict:
        conn.settimeout(self.io_timeout)
        try:
            request = recv_json(conn, protocol.MAX_REQUEST_BYTES)
        except (OSError, ProtocolError) as e:
            logging.warning("tool runner received no valid request: %s", e)
            return {"status": protocol.STATUS_BAD_REQUEST, "message": str(e)}

        error = protocol.validate_request(request)
        if error is not None:
            logging.warning("tool runner rejected a request: %s", error)
            return {"status": protocol.STATUS_BAD_REQUEST, "message": error}

        tool = os.path.basename(request["argv"][0])
        deadline = time.monotonic() + request["timeout"]
        limits = SandboxConfig.model_validate(request["limits"])

        def cancel() -> bool:
            return self._stopping.is_set() or _client_gone(conn)

        def stopped_or_cancelled() -> dict:
            status = protocol.STATUS_STOPPED if self._stopping.is_set() else protocol.STATUS_CANCELLED
            return {"status": status, "tool": tool}

        if limits.memory_limit > self.budget:
            return {"status": protocol.STATUS_ERROR, "tool": tool,
                    "message": f"its memory limit of {limits.memory_limit} bytes is more than the {self.budget} bytes "
                               "the tool runner has"}

        admitted = self._reserve(limits.memory_limit, deadline, cancel)
        if admitted is None:
            return stopped_or_cancelled()
        if not admitted:
            return {"status": protocol.STATUS_BUSY, "tool": tool,
                    "message": f"the tool runner's {self.budget} bytes of memory were taken by other runs "
                               f"for all of its {request['timeout']:.0f} seconds"}

        try:
            return self._run_in_cgroup(request, tool, limits, deadline, cancel, stopped_or_cancelled)
        finally:
            with self._memory:
                self._reserved -= limits.memory_limit
                self._memory.notify_all()

    def _reserve(self, memory: int, deadline: float, cancel) -> Optional[bool]:
        """Reserves memory for a run once the runs in progress leave enough. False when they do not before
        the run would have less than _MIN_RUN_SECONDS left, None when it is cancelled first."""
        with self._memory:
            while self._reserved + memory > self.budget:
                if cancel():
                    return None

                remaining = deadline - time.monotonic() - _MIN_RUN_SECONDS
                if remaining <= 0:
                    return False

                logging.debug("a tool run waits for %d bytes of memory (%d of %d reserved)", memory, self._reserved,
                              self.budget)
                self._memory.wait(min(remaining, _POLL_SECONDS))

            self._reserved += memory
            return True

    def _run_in_cgroup(self, request: dict, tool: str, limits: SandboxConfig, deadline: float, cancel,
                       stopped_or_cancelled) -> dict:
        try:
            cgroup = self.cgroups.create(limits.memory_limit)
        except OSError as e:
            logging.error("tool runner unable to create a cgroup for %s under %s: %s", tool, self.cgroups.parent, e,
                          exc_info=e)
            return {"status": protocol.STATUS_ERROR, "tool": tool, "message": f"unable to create a cgroup for it: {e}"}

        try:
            timeout = datetime.timedelta(seconds=deadline - time.monotonic())
            argv = build_sandbox_argv(request["argv"], request["workdir"], limits, timeout,
                                      read_files=request["read_files"], read_dirs=request["read_dirs"],
                                      write_dirs=request["write_dirs"], cpu_seconds=request.get("cpu_seconds"),
                                      cgroup=cgroup)
            try:
                result = run_sandboxed(argv, request.get("stdin"), request["env"], request["cwd"], timeout,
                                       limits.max_output_bytes, cancel=cancel)
                response = {"status": protocol.STATUS_OK, "tool": tool, **_result_fields(result)}
            except SandboxCancelled:
                return stopped_or_cancelled()
            except SandboxOutputExceeded as e:
                response = {"status": protocol.STATUS_OUTPUT_EXCEEDED, "tool": tool, **_result_fields(e.result)}
            except RuntimeError as e:
                # run_sandboxed's timeout
                response = {"status": protocol.STATUS_TIMEOUT, "tool": tool, "message": str(e)}
            except OSError as e:
                logging.error("tool runner unable to start %s: %s", tool, e, exc_info=e)
                return {"status": protocol.STATUS_ERROR, "tool": tool, "message": f"unable to start it: {e}"}

            # the memory kill decides, whatever the launcher made of the SIGKILL
            if self.cgroups.oom_killed(cgroup):
                response = {"status": protocol.STATUS_MEMORY, "tool": tool,
                            "message": f"it used more than its memory limit of {limits.memory_limit} bytes"}

            return response
        finally:
            try:
                self.cgroups.remove(cgroup)
            except OSError as e:
                logging.error("tool runner unable to remove the cgroup %s of %s: %s", cgroup, tool, e, exc_info=e)
