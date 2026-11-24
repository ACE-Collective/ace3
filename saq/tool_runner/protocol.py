"""The tool runner's wire protocol (docs/TOOL_SANDBOX.md), in the yara scanner's frames: a 4 byte
big-endian length and that many bytes of JSON (saq/yara_scanning/protocol.py).

1. The client connects and sends one request: the command, the paths it may read and write, its
   environment and cwd, its timeout and its sandbox limits. Every path means the same file on both
   ends, which share SAQ_HOME and the data directory.
2. The server runs it and sends one response, then closes the connection.

A client that no longer wants the answer (its analysis was cancelled) shuts down its side of the
connection. The server stops the command and still answers, once everything the command started
is gone.
"""

from typing import Any

from pydantic import ValidationError

from saq.configuration.schema import SandboxConfig

PROTOCOL_VERSION = 1

# the name of the socket clients connect to, inside the service's socket_dir
SOCKET_NAME = "runner.sock"

# the command ran and exited (returncode, stdout, stderr)
STATUS_OK = "ok"
# it wrote more than max_output_bytes and was stopped (stdout and stderr up to then)
STATUS_OUTPUT_EXCEEDED = "output_exceeded"
# it ran past its timeout and was stopped
STATUS_TIMEOUT = "timeout"
# the kernel killed it for going over its memory limit
STATUS_MEMORY = "memory"
# the client shut down its side, and the command was stopped
STATUS_CANCELLED = "cancelled"
# the runner's memory was taken by other runs until there was no time left to run this one
STATUS_BUSY = "busy"
# the runner is stopping, and stopped the command
STATUS_STOPPED = "stopped"
# the runner could not run it (message)
STATUS_ERROR = "error"
# the request is malformed (message)
STATUS_BAD_REQUEST = "bad_request"

# stdin is the largest part of a request: a correlation stream transform sends every event in it
MAX_REQUEST_BYTES = 256 * 1024 * 1024
# JSON escapes a byte of control characters in six
JSON_EXPANSION = 6

_PATH_LISTS = ("read_files", "read_dirs", "write_dirs")


def max_response_bytes(max_output_bytes: int) -> int:
    """The largest response to a command limited to max_output_bytes of each of stdout and stderr."""
    return 2 * max_output_bytes * JSON_EXPANSION + 1024 * 1024


def _is_strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def validate_request(request: dict) -> str | None:
    """Why the request is invalid, or None when it is valid."""
    if request.get("v") != PROTOCOL_VERSION:
        return f"unsupported protocol version {request.get('v')!r}"

    if not (_is_strings(request.get("argv")) and request["argv"]):
        return "argv must be a non-empty list of strings"

    env = request.get("env")
    if not (isinstance(env, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())):
        return "env must be an object of strings"

    for name in ("cwd", "workdir"):
        if not (isinstance(request.get(name), str) and request[name].startswith("/")):
            return f"{name} must be an absolute path"

    for name in _PATH_LISTS:
        if not _is_strings(request.get(name)):
            return f"{name} must be a list of strings"

    if request.get("stdin") is not None and not isinstance(request["stdin"], str):
        return "stdin must be a string"

    timeout = request.get("timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        return "timeout must be a positive number"

    cpu_seconds = request.get("cpu_seconds")
    if cpu_seconds is not None and (isinstance(cpu_seconds, bool) or not isinstance(cpu_seconds, int) or cpu_seconds <= 0):
        return "cpu_seconds must be a positive integer"

    try:
        SandboxConfig.model_validate(request.get("limits"))
    except ValidationError as e:
        return f"invalid limits: {e}"

    return None
