"""The yara scanner wire protocol (docs/YARA_SCANNER.md).

Every message is a frame: a 4 byte big-endian length followed by that many bytes.

1. The server accepts the connection and immediately sends the single byte ACK. That byte is
   what tells a client "a worker has picked this up" apart from "nothing is serving the socket".
2. The client sends a JSON request frame. OP_SCAN_FILE carries the absolute path, and the server
   reads the file there. OP_SCAN_DATA is followed by one more frame holding the raw bytes to scan.
3. The server sends one JSON response frame and closes the connection.

Matched string data is binary, so each (offset, identifier, data) tuple of a match travels as
[offset, identifier, base64(data)] and is turned back into a tuple on the client. A match
therefore looks exactly like what YaraScanner.scan_results returns locally.
"""

import base64
import json
import socket
import struct
from typing import Any

PROTOCOL_VERSION = 1

# the name of the socket clients connect to, inside the service's socket_dir
SOCKET_NAME = "scanner.sock"

ACK = b"A"

OP_SCAN_FILE = "scan_file"
OP_SCAN_DATA = "scan_data"
VALID_OPS = (OP_SCAN_FILE, OP_SCAN_DATA)

STATUS_OK = "ok"
STATUS_TIMEOUT = "timeout"
STATUS_ERROR = "error"
STATUS_BAD_REQUEST = "bad_request"

# a JSON request is small: scan_file carries a path, scan_data carries only metadata.
# the bytes of a scan_data request are a separate frame and do not count against this limit
MAX_REQUEST_BYTES = 1024 * 1024
# a response carries every matched string of every matched rule
MAX_RESPONSE_BYTES = 256 * 1024 * 1024

_LENGTH = struct.Struct("!I")


class ProtocolError(Exception):
    """The other end sent something that does not follow the protocol."""


class ConnectionClosedError(ProtocolError):
    """The other end closed the connection in the middle of a message."""


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Reads exactly size bytes from sock."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(min(remaining, 1024 * 1024))
        if not chunk:
            raise ConnectionClosedError(f"connection closed after {size - remaining} of {size} bytes")

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def send_frame(sock: socket.socket, data: bytes):
    sock.sendall(_LENGTH.pack(len(data)) + data)


def recv_frame(sock: socket.socket, max_size: int) -> bytes:
    (size,) = _LENGTH.unpack(recv_exact(sock, _LENGTH.size))
    if size > max_size:
        raise ProtocolError(f"frame of {size} bytes exceeds the limit of {max_size}")

    return recv_exact(sock, size)


def send_json(sock: socket.socket, message: dict):
    send_frame(sock, json.dumps(message).encode())


def recv_json(sock: socket.socket, max_size: int) -> dict:
    data = recv_frame(sock, max_size)
    try:
        message = json.loads(data)
    except ValueError as e:
        raise ProtocolError(f"invalid json: {e}") from e

    if not isinstance(message, dict):
        raise ProtocolError(f"expected a json object, got {type(message).__name__}")

    return message


def encode_matches(matches: list[dict]) -> list[dict]:
    """Makes YaraScanner.scan_results JSON serializable."""
    result = []
    for match in matches:
        match = dict(match)
        match["strings"] = [
            [offset, identifier, base64.b64encode(data).decode("ascii")]
            for offset, identifier, data in match.get("strings") or []]
        result.append(match)

    return result


def decode_matches(matches: Any) -> list[dict]:
    """The inverse of encode_matches."""
    if not isinstance(matches, list):
        raise ProtocolError(f"expected a list of matches, got {type(matches).__name__}")

    result = []
    for match in matches:
        if not isinstance(match, dict):
            raise ProtocolError(f"expected a match object, got {type(match).__name__}")

        match = dict(match)
        try:
            match["strings"] = [
                (int(offset), str(identifier), base64.b64decode(data, validate=True))
                for offset, identifier, data in match.get("strings") or []]
        except (TypeError, ValueError) as e:
            raise ProtocolError(f"invalid strings in match for rule {match.get('rule')}: {e}") from e

        result.append(match)

    return result


def validate_request(request: dict) -> str | None:
    """Returns why the request is invalid, or None if it is valid."""
    if request.get("v") != PROTOCOL_VERSION:
        return f"unsupported protocol version {request.get('v')!r}"

    op = request.get("op")
    if op not in VALID_OPS:
        return f"unknown op {op!r}"

    if op == OP_SCAN_FILE and not (isinstance(request.get("path"), str) and request["path"]):
        return "scan_file requires a path"

    ext_vars = request.get("ext_vars")
    if ext_vars is not None and not isinstance(ext_vars, dict):
        return "ext_vars must be an object"

    meta_tags = request.get("meta_tags")
    if meta_tags is not None and not (isinstance(meta_tags, list) and all(isinstance(_, str) for _ in meta_tags)):
        return "meta_tags must be a list of strings"

    timeout = request.get("timeout")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0):
        return "timeout must be a positive integer"

    return None
