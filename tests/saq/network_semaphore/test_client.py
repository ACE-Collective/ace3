import logging
import socket
import threading
from unittest.mock import Mock

import pytest

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_NETWORK_SEMAPHORE
from saq.environment import get_global_runtime_settings
from saq.network_semaphore import NetworkSemaphore, NetworkSemaphoreClient
from saq.network_semaphore import client as client_module
from saq.network_semaphore.fallback import get_undefined_fallback_semaphores, initialize_fallback_semaphores

# long enough for the client to finish everything it does after a socket timeout
CLIENT_BOUND_SECONDS = 10


@pytest.fixture(autouse=True)
def clear_fallback_semaphores():
    initialize_fallback_semaphores(force=True)


class FakeServer:
    """Accepts one connection and hands it to a handler, so a test decides what the server says."""

    def __init__(self, handler):
        self.handler = handler
        self.stop = threading.Event()
        self.received = []
        self.disconnected = threading.Event()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(CLIENT_BOUND_SECONDS)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        conn, _ = self.listener.accept()
        with conn:
            conn.settimeout(CLIENT_BOUND_SECONDS)
            self.handler(self, conn)

    def recv(self, conn) -> str:
        data = conn.recv(128).decode("ascii")
        if data == "":
            self.disconnected.set()
        else:
            self.received.append(data)
        return data

    def wait_for_disconnect(self, conn):
        while self.recv(conn) != "":
            pass

    def close(self):
        self.stop.set()
        self.thread.join(CLIENT_BOUND_SECONDS)
        self.listener.close()


@pytest.fixture
def fake_server(monkeypatch):
    servers = []

    def start(handler) -> FakeServer:
        server = FakeServer(handler)
        servers.append(server)
        config = get_service_config(SERVICE_NETWORK_SEMAPHORE)
        monkeypatch.setattr(config, "remote_address", "127.0.0.1")
        monkeypatch.setattr(config, "remote_port", server.port)
        return server

    yield start

    for server in servers:
        server.close()


def silent_after_acquire(server, conn):
    server.recv(conn)
    server.stop.wait(CLIENT_BOUND_SECONDS * 2)


def lock_then(after_lock):
    def handler(server, conn):
        server.recv(conn)
        conn.sendall(b"wait|locked|")
        after_lock(server, conn)
    return handler


def keep_waiting(server, conn):
    server.recv(conn)
    while not server.stop.is_set():
        try:
            conn.sendall(b"wait|")
        except OSError:
            # the client closed the connection
            server.disconnected.set()
            return
        server.stop.wait(0.1)


def run_bounded(target) -> list:
    """Runs target in a thread and fails the test if it is still running after CLIENT_BOUND_SECONDS."""
    result = []
    thread = threading.Thread(target=lambda: result.append(target()), daemon=True)
    thread.start()
    thread.join(CLIENT_BOUND_SECONDS)
    assert not thread.is_alive(), "the client is still waiting on the server"
    return result


@pytest.mark.unit
def test_acquire_from_a_silent_server_falls_back(fake_server, monkeypatch, caplog):
    monkeypatch.setattr(client_module, "SOCKET_TIMEOUT_SECONDS", 0.5, raising=False)
    server = fake_server(silent_after_acquire)
    client = NetworkSemaphoreClient()

    with caplog.at_level(logging.WARNING):
        assert run_bounded(lambda: client.acquire("test")) == [True]

    assert server.received == ["acquire:test|"]
    assert client.fallback_semaphore is not None
    assert any("unable to acquire network semaphore test" in r.getMessage() for r in caplog.records)
    client.release()


@pytest.mark.unit
def test_release_to_a_silent_server_returns(fake_server, monkeypatch, caplog):
    monkeypatch.setattr(client_module, "SOCKET_TIMEOUT_SECONDS", 0.5, raising=False)
    server = fake_server(lock_then(silent_after_acquire))
    client = NetworkSemaphoreClient()
    assert client.acquire("test")
    assert client.fallback_semaphore is None

    with caplog.at_level(logging.ERROR):
        run_bounded(client.release)

    assert server.received[-1] == "release|"
    assert any("error trying to release semaphore test" in r.getMessage() for r in caplog.records)
    assert not client.semaphore_acquired
    assert client.release_event.is_set()
    assert not client.failsafe_thread.is_alive()


@pytest.mark.unit
def test_acquire_and_release(fake_server, caplog):
    def answer_release(server, conn):
        server.recv(conn)
        conn.sendall(b"ok|")
        server.wait_for_disconnect(conn)

    server = fake_server(lock_then(answer_release))
    client = NetworkSemaphoreClient()

    with caplog.at_level(logging.DEBUG):
        assert client.acquire("test")
        # a second acquire is a no-op
        assert client.acquire("test")
        client.release()

    assert server.received == ["acquire:test|", "release|"]
    assert server.disconnected.wait(CLIENT_BOUND_SECONDS)
    assert client.fallback_semaphore is None
    assert not client.semaphore_acquired
    messages = [r.getMessage() for r in caplog.records]
    assert "semaphore test already acquired" in messages
    assert "successfully released semaphore test" in messages


@pytest.mark.unit
@pytest.mark.parametrize("answer, message", [
    (b"nope|", "invalid response from server"),
    (b"", "detected client disconnect"),
])
def test_release_without_ok(fake_server, caplog, answer, message):
    def bad_answer(server, conn):
        server.recv(conn)
        if answer:
            conn.sendall(answer)

    fake_server(lock_then(bad_answer))
    client = NetworkSemaphoreClient()
    assert client.acquire("test")

    with caplog.at_level(logging.DEBUG):
        client.release()

    assert message in [r.getMessage() for r in caplog.records]
    assert not client.semaphore_acquired
    assert not client.failsafe_thread.is_alive()


@pytest.mark.unit
def test_acquire_times_out_while_the_server_says_wait(fake_server, caplog):
    server = fake_server(keep_waiting)
    client = NetworkSemaphoreClient()

    with caplog.at_level(logging.WARNING):
        assert not client.acquire("test", timeout=0)

    # the request is abandoned by closing the connection, and no fallback is taken
    assert server.disconnected.wait(CLIENT_BOUND_SECONDS)
    assert client.fallback_semaphore is None
    assert not client.semaphore_acquired
    messages = [r.getMessage() for r in caplog.records]
    assert "attempt to acquire semaphore test timed out" in messages
    assert "acquiring fallback semaphore test" not in messages


@pytest.mark.unit
def test_cancelled_while_the_server_says_wait(fake_server):
    server = fake_server(keep_waiting)
    # not cancelled when the request is sent, cancelled after the first wait
    answers = iter([False, True])
    client = NetworkSemaphoreClient(cancel_request_callback=lambda: next(answers))

    assert not client.acquire("test")

    assert server.disconnected.wait(CLIENT_BOUND_SECONDS)
    assert not client.semaphore_acquired
    assert len(get_undefined_fallback_semaphores()) == 0


@pytest.mark.unit
@pytest.mark.parametrize("answer, error", [
    (b"bogus|", "received invalid command bogus|"),
    (b"", "detected client disconnect"),
])
def test_bad_answer_to_acquire_falls_back(fake_server, caplog, answer, error):
    def handler(server, conn):
        server.recv(conn)
        if answer:
            conn.sendall(answer)

    fake_server(handler)
    client = NetworkSemaphoreClient()

    with caplog.at_level(logging.WARNING):
        assert client.acquire("test")

    assert client.fallback_semaphore is not None
    assert f"unable to acquire network semaphore test: {error}" in [r.getMessage() for r in caplog.records]
    client.release()


@pytest.mark.unit
def test_fallback_failure_is_reported(monkeypatch, caplog):
    # the semaphore service is not running in unit tests, so this goes to the fallback
    monkeypatch.setattr(client_module, "get_defined_fallback_semaphores", Mock(side_effect=RuntimeError("broken")))
    client = NetworkSemaphoreClient()

    with caplog.at_level(logging.ERROR):
        assert not client.acquire("test")

    records = [r for r in caplog.records if "unable to use fallback semaphore test" in r.getMessage()]
    assert len(records) == 1
    assert records[0].exc_info is not None
    assert not client.semaphore_acquired


def held_client(sendall) -> NetworkSemaphoreClient:
    client = NetworkSemaphoreClient()
    client.semaphore_name = "test"
    client.semaphore_acquired = True
    client.socket = Mock(sendall=sendall)
    # one keep-alive interval passes, then the semaphore is released
    client.release_event = Mock(wait=Mock(side_effect=[False, True]))
    return client


@pytest.mark.unit
def test_failsafe_sends_keep_alive():
    client = held_client(Mock())

    client.failsafe_loop()

    client.socket.sendall.assert_called_once_with(b"wait|")


@pytest.mark.unit
def test_failsafe_does_not_send_for_a_fallback_semaphore():
    client = held_client(Mock())
    client.fallback_semaphore = Mock()

    client.failsafe_loop()

    client.socket.sendall.assert_not_called()


@pytest.mark.unit
def test_failsafe_closes_a_broken_connection(caplog):
    client = held_client(Mock(side_effect=BrokenPipeError("gone")))
    client.socket.close.side_effect = OSError("already closed")

    with caplog.at_level(logging.WARNING):
        client.failsafe_loop()

    client.socket.close.assert_called_once()
    assert "failsafe on semaphore test error gone" in [r.getMessage() for r in caplog.records]


@pytest.mark.unit
def test_cancel_request():
    client = NetworkSemaphoreClient()
    assert not client.request_is_cancelled
    client.cancel_request()
    assert client.request_is_cancelled
    assert not client.acquire("test")


@pytest.mark.unit
def test_context_manager_acquires_and_releases(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "semaphores_enabled", True)
    semaphore = NetworkSemaphore("test")
    semaphore.semaphore = Mock(semaphore_acquired=True)

    with semaphore:
        semaphore.semaphore.acquire.assert_called_once_with("test")

    semaphore.semaphore.release.assert_called_once()


@pytest.mark.unit
def test_context_manager_raises_when_not_acquired(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "semaphores_enabled", True)
    semaphore = NetworkSemaphore("test")
    semaphore.semaphore = Mock(acquire=Mock(return_value=False))

    with pytest.raises(RuntimeError, match="failed to acquire network semaphore: test"):
        with semaphore:
            pass


@pytest.mark.unit
def test_context_manager_does_nothing_when_semaphores_are_disabled(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "semaphores_enabled", False)
    semaphore = NetworkSemaphore("test")
    semaphore.semaphore = Mock(semaphore_acquired=False)

    with semaphore:
        pass

    semaphore.semaphore.acquire.assert_not_called()
    semaphore.semaphore.release.assert_not_called()
