"""What runs a sandboxed tool on the tool runner (docs/TOOL_SANDBOX.md).

run_on_runner() raises what run_sandboxed() raises for the same outcome (SandboxCancelled,
SandboxOutputExceeded, a RuntimeError for a timeout), plus:

- ToolMemoryExceeded: the kernel killed the tool for going over its memory limit. The file's doing,
  like a timeout.
- ToolRunnerUnavailable: nothing is serving the socket, or the runner stopped during the run.
- ToolRunnerBusy: other runs held the runner's memory for as long as this one could wait.
- ToolRunnerFailed: the runner could not run the tool, or did not answer.

The last three are ToolRunnerError, the node's doing rather than the file's. All of them are
RuntimeErrors, as a timeout is, for a caller that treats every failure of a command alike.
"""

import datetime
import os
import select
import socket
import time
from collections.abc import Callable, Sequence
from typing import Optional

from saq.configuration.config import get_service_config
from saq.configuration.schema import SandboxConfig
from saq.constants import SERVICE_TOOL_RUNNER
from saq.environment import get_data_dir
from saq.sandbox.runner import LAUNCHER_STOP_SECONDS, SandboxCancelled, SandboxOutputExceeded, SandboxResult
from saq.tool_runner import protocol
from saq.yara_scanning.protocol import ProtocolError, recv_json, send_json

# how long connecting and sending the request may take
CONNECT_TIMEOUT_SECONDS = 10

# how much longer than the timeout the client waits for the answer: the runner stops a command
# that ran out of time (LAUNCHER_STOP_SECONDS at most) and removes its cgroup
RESPONSE_MARGIN_SECONDS = LAUNCHER_STOP_SECONDS + 10

# how often a wait for the answer checks whether to cancel
_CANCEL_POLL_SECONDS = 0.5


class ToolMemoryExceeded(RuntimeError):
    pass


class ToolRunnerError(RuntimeError):
    pass


class ToolRunnerUnavailable(ToolRunnerError):
    pass


class ToolRunnerBusy(ToolRunnerError):
    pass


class ToolRunnerFailed(ToolRunnerError):
    pass


def get_socket_path() -> str:
    return os.path.join(get_data_dir(), get_service_config(SERVICE_TOOL_RUNNER).socket_dir, protocol.SOCKET_NAME)


def _wait_for_answer(sock: socket.socket, give_up: float, cancel: Optional[Callable[[], bool]]) -> bool:
    """Waits until the answer starts to arrive; True if cancel returned True first, and the runner was told."""
    while True:
        if cancel is not None and cancel():
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass  # the runner closed it, and the answer says why

            return True

        remaining = give_up - time.monotonic()
        if remaining <= 0:
            raise ToolRunnerFailed(f"no answer from the tool runner within {RESPONSE_MARGIN_SECONDS} seconds of the "
                                   "tool's timeout")

        readable, _, _ = select.select([sock], [], [], min(remaining, _CANCEL_POLL_SECONDS))
        if readable:
            return False


def run_on_runner(argv: Sequence[str | os.PathLike], *, env: dict[str, str], cwd: str, workdir: str,
                  timeout: datetime.timedelta, config: SandboxConfig, stdin_data: Optional[str] = None,
                  read_files: Sequence[str] = (), read_dirs: Sequence[str] = (), write_dirs: Sequence[str] = (),
                  cpu_seconds: Optional[int] = None, cancel: Optional[Callable[[], bool]] = None,
                  socket_path: Optional[str] = None) -> SandboxResult:
    """Runs argv in the sandbox on the tool runner, as build_sandbox_argv() and run_sandboxed() would here,
    in a cgroup whose memory.max is config.memory_limit. argv[0] is an absolute path, and every path means
    the same file to the runner. cancel is polled while the tool runs; once it returns True the runner
    stops the tool, and SandboxCancelled is raised once it has."""
    if socket_path is None:
        socket_path = get_socket_path()

    request = {
        "v": protocol.PROTOCOL_VERSION,
        "argv": [os.fspath(arg) for arg in argv],
        "env": env,
        "cwd": os.fspath(cwd),
        "workdir": os.fspath(workdir),
        "read_files": [os.fspath(path) for path in read_files],
        "read_dirs": [os.fspath(path) for path in read_dirs],
        "write_dirs": [os.fspath(path) for path in write_dirs],
        "stdin": stdin_data,
        "timeout": timeout.total_seconds(),
        "cpu_seconds": cpu_seconds,
        # only what every sandbox has, not a caller's own settings (a work_dir)
        "limits": config.model_dump(include=set(SandboxConfig.model_fields)),
    }

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            sock.connect(socket_path)
            send_json(sock, request)
        except OSError as e:
            raise ToolRunnerUnavailable(f"the tool runner at {socket_path} is unavailable: {e}") from e

        cancelled = _wait_for_answer(sock, time.monotonic() + timeout.total_seconds() + RESPONSE_MARGIN_SECONDS, cancel)
        # an answer that has started arrives at once; one to a cancel once the tool is stopped
        sock.settimeout(RESPONSE_MARGIN_SECONDS)
        try:
            response = recv_json(sock, protocol.max_response_bytes(config.max_output_bytes))
        except (OSError, ProtocolError) as e:
            raise ToolRunnerFailed(f"the tool runner closed the connection without answering: {e}") from e
    finally:
        sock.close()

    status = response.get("status")
    message = response.get("message")
    if status in (protocol.STATUS_OK, protocol.STATUS_OUTPUT_EXCEEDED):
        result = SandboxResult(returncode=response.get("returncode"), stdout=response.get("stdout") or "",
                               stderr=response.get("stderr") or "",
                               output_exceeded=status == protocol.STATUS_OUTPUT_EXCEEDED)
        if result.output_exceeded:
            raise SandboxOutputExceeded(f"command wrote more than {config.max_output_bytes} bytes of output", result)
        if cancelled:
            # it finished before the runner saw the cancel
            raise SandboxCancelled("command cancelled")

        return result

    if status == protocol.STATUS_CANCELLED:
        raise SandboxCancelled("command cancelled")
    if status == protocol.STATUS_TIMEOUT:
        # the time it was given, rather than what was left of it once it got its memory
        raise RuntimeError(f"command timed out after {timeout}")
    if status == protocol.STATUS_MEMORY:
        raise ToolMemoryExceeded(message)
    if status == protocol.STATUS_BUSY:
        raise ToolRunnerBusy(message)
    if status == protocol.STATUS_STOPPED:
        raise ToolRunnerUnavailable("the tool runner stopped while the tool ran")
    if status == protocol.STATUS_ERROR:
        raise ToolRunnerFailed(message)
    if status == protocol.STATUS_BAD_REQUEST:
        raise ToolRunnerFailed(f"the tool runner rejected the request: {message}")

    raise ToolRunnerFailed(f"the tool runner answered with an unknown status {status!r}")
