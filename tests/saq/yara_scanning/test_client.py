"""The client against stand-in servers, for the failures a real one does not produce on demand."""

import os
import socket
import threading

import pytest

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.yara_scanning import client, protocol
from saq.yara_scanning.client import YaraScanCrashed, YaraScanError, YaraScanTimeout, YaraServiceUnavailable


@pytest.fixture
def socket_path(tmp_path) -> str:
    result = str(tmp_path / "scanner.sock")
    assert len(result) < 108
    return result


@pytest.fixture
def stub_server(socket_path):
    """Starts a server that accepts one connection and hands it to the given function."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    listener.listen(1)
    threads = []

    def _start(handler):
        def _run():
            conn, _ = listener.accept()
            with conn:
                handler(conn)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        threads.append(thread)

    yield _start

    listener.close()
    for thread in threads:
        thread.join(5)


def _respond(response: dict):
    def _handler(conn):
        conn.sendall(protocol.ACK)
        protocol.recv_json(conn, protocol.MAX_REQUEST_BYTES)
        protocol.send_json(conn, response)

    return _handler


@pytest.mark.unit
def test_no_socket_is_unavailable(socket_path):
    with pytest.raises(YaraServiceUnavailable):
        client.scan_file("/etc/hostname", socket_path=socket_path)


@pytest.mark.unit
def test_socket_nobody_listens_on_is_unavailable(socket_path):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    listener.close()

    with pytest.raises(YaraServiceUnavailable):
        client.scan_file("/etc/hostname", socket_path=socket_path)


@pytest.mark.unit
def test_no_free_worker_is_unavailable(socket_path, monkeypatch):
    """Nothing ever accepts the connection: it waits in the backlog until client_queue_timeout."""
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "client_queue_timeout", 0.5)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    listener.listen(1)

    try:
        with pytest.raises(YaraServiceUnavailable):
            client.scan_file("/etc/hostname", socket_path=socket_path)
    finally:
        listener.close()


@pytest.mark.unit
def test_worker_that_never_answers_times_out(socket_path, stub_server, monkeypatch):
    monkeypatch.setattr(client, "RESPONSE_MARGIN_SECONDS", 0.5)
    done = threading.Event()

    def _stall(conn):
        conn.sendall(protocol.ACK)
        done.wait(10)

    stub_server(_stall)
    try:
        with pytest.raises(YaraScanTimeout):
            client.scan_file("/etc/hostname", timeout=1, socket_path=socket_path)
    finally:
        done.set()


@pytest.mark.unit
def test_worker_that_dies_is_a_crash(socket_path, stub_server):
    def _die(conn):
        conn.sendall(protocol.ACK)
        protocol.recv_json(conn, protocol.MAX_REQUEST_BYTES)

    stub_server(_die)
    with pytest.raises(YaraScanCrashed):
        client.scan_file("/etc/hostname", socket_path=socket_path)


@pytest.mark.unit
def test_request_shape(socket_path, stub_server):
    received = {}

    def _handler(conn):
        conn.sendall(protocol.ACK)
        received["request"] = protocol.recv_json(conn, protocol.MAX_REQUEST_BYTES)
        received["data"] = protocol.recv_frame(conn, 1024)
        protocol.send_json(conn, {"status": protocol.STATUS_OK, "matches": []})

    stub_server(_handler)
    assert client.scan_data(b"\x00data", meta_tags=["a=b"], ext_vars={"filename": "x"}, socket_path=socket_path) == []

    assert protocol.validate_request(received["request"]) is None
    assert received["request"]["op"] == protocol.OP_SCAN_DATA
    assert received["request"]["meta_tags"] == ["a=b"]
    assert received["request"]["ext_vars"] == {"filename": "x"}
    assert received["request"]["timeout"] == get_service_config(SERVICE_YARA_SCANNER).default_timeout
    assert received["data"] == b"\x00data"


@pytest.mark.unit
def test_relative_path_is_sent_absolute(socket_path, stub_server, tmp_path, monkeypatch):
    received = {}

    def _handler(conn):
        conn.sendall(protocol.ACK)
        received["request"] = protocol.recv_json(conn, protocol.MAX_REQUEST_BYTES)
        protocol.send_json(conn, {"status": protocol.STATUS_OK, "matches": []})

    stub_server(_handler)
    monkeypatch.chdir(tmp_path)
    client.scan_file("target", socket_path=socket_path)
    assert received["request"]["path"] == os.path.join(str(tmp_path), "target")


@pytest.mark.unit
@pytest.mark.parametrize("response, expected", [
    ({"status": protocol.STATUS_TIMEOUT, "error": {"message": "timed out"}}, YaraScanTimeout),
    ({"status": protocol.STATUS_ERROR, "error": {"message": "could not open file"}}, YaraScanError),
    ({"status": protocol.STATUS_BAD_REQUEST, "error": {"message": "bad"}}, protocol.ProtocolError),
    ({"status": "something else"}, protocol.ProtocolError),
])
def test_error_statuses(socket_path, stub_server, response, expected):
    stub_server(_respond(response))
    with pytest.raises(expected):
        client.scan_file("/etc/hostname", socket_path=socket_path)


@pytest.mark.unit
def test_wrong_acknowledgement(socket_path, stub_server):
    stub_server(lambda conn: conn.sendall(b"X"))
    with pytest.raises(protocol.ProtocolError):
        client.scan_file("/etc/hostname", socket_path=socket_path)
