"""The client side of the yara scanner service (docs/YARA_SCANNER.md).

What went wrong decides what the caller should do next, so each outcome has its own exception.
None of them is an OSError, so they cannot be mistaken for socket.error or TimeoutError.

- YaraServiceUnavailable: nothing is serving the socket. Scan locally instead.
- YaraScanTimeout: yara (or the server) ran out of time scanning this target.
- YaraScanCrashed: a worker took the request and died before answering. Do not retry the same
  target in-process; it may crash the caller the same way.
- YaraScanError: yara failed to scan the target.
- ProtocolError: the server answered with something that is not a valid response.
"""

import os
import socket
from typing import Optional

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.environment import get_data_dir
from saq.yara_scanning import protocol
from saq.yara_scanning.protocol import ConnectionClosedError, ProtocolError

# how much longer than the scan timeout the client waits for an answer
RESPONSE_MARGIN_SECONDS = 5


class YaraClientError(Exception):
    pass


class YaraServiceUnavailable(YaraClientError):
    pass


class YaraScanTimeout(YaraClientError):
    pass


class YaraScanCrashed(YaraClientError):
    pass


class YaraScanError(YaraClientError):
    pass


def get_socket_path() -> str:
    return os.path.join(get_data_dir(), get_service_config(SERVICE_YARA_SCANNER).socket_dir, protocol.SOCKET_NAME)


def scan_file(path: str, *, meta_tags: Optional[list[str]] = None, ext_vars: Optional[dict] = None,
              timeout: Optional[int] = None, socket_path: Optional[str] = None) -> list[dict]:
    """Sends the absolute path of the file and returns the matches, shaped like
    YaraScanner.scan_results. The server reads the file at that same path. An empty list means
    nothing matched."""
    request = {"op": protocol.OP_SCAN_FILE, "path": os.path.abspath(path)}
    return _request(request, None, meta_tags, ext_vars, timeout, socket_path)


def scan_data(data: bytes | str, *, meta_tags: Optional[list[str]] = None, ext_vars: Optional[dict] = None,
              timeout: Optional[int] = None, socket_path: Optional[str] = None) -> list[dict]:
    """Sends the bytes to the server and returns the matches, shaped like YaraScanner.scan_results."""
    if isinstance(data, str):
        data = data.encode()

    return _request({"op": protocol.OP_SCAN_DATA}, data, meta_tags, ext_vars, timeout, socket_path)


def _request(request: dict, data: Optional[bytes], meta_tags: Optional[list[str]], ext_vars: Optional[dict],
             timeout: Optional[int], socket_path: Optional[str]) -> list[dict]:
    config = get_service_config(SERVICE_YARA_SCANNER)
    if socket_path is None:
        socket_path = get_socket_path()

    scan_timeout = timeout or config.default_timeout
    request = {**request, "v": protocol.PROTOCOL_VERSION, "ext_vars": ext_vars or {},
               "meta_tags": list(meta_tags) if meta_tags else None, "timeout": scan_timeout}

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # the connection waits in the backlog until a worker is free, and every worker may be busy
        # scanning: client_queue_timeout is how long that wait may take
        sock.settimeout(config.client_queue_timeout)
        try:
            sock.connect(socket_path)
            ack = protocol.recv_exact(sock, 1)
        except (OSError, ProtocolError) as e:
            raise YaraServiceUnavailable(f"yara scanner at {socket_path} is unavailable: {e}") from e

        if ack != protocol.ACK:
            raise ProtocolError(f"unexpected acknowledgement {ack!r}")

        sock.settimeout(scan_timeout + RESPONSE_MARGIN_SECONDS)
        try:
            protocol.send_json(sock, request)
            if data is not None:
                protocol.send_frame(sock, data)

            response = protocol.recv_json(sock, protocol.MAX_RESPONSE_BYTES)
        except TimeoutError as e:
            raise YaraScanTimeout(f"no answer from the yara scanner within {scan_timeout + RESPONSE_MARGIN_SECONDS} seconds") from e
        except (OSError, ConnectionClosedError) as e:
            raise YaraScanCrashed(f"the yara scanner closed the connection without answering: {e}") from e
    finally:
        sock.close()

    status = response.get("status")
    if status == protocol.STATUS_OK:
        return protocol.decode_matches(response.get("matches"))

    message = (response.get("error") or {}).get("message")
    if status == protocol.STATUS_TIMEOUT:
        raise YaraScanTimeout(f"yara scan timed out: {message}")

    if status == protocol.STATUS_ERROR:
        raise YaraScanError(message)

    if status == protocol.STATUS_BAD_REQUEST:
        raise ProtocolError(f"the yara scanner rejected the request: {message}")

    raise ProtocolError(f"unexpected status {status!r}")
