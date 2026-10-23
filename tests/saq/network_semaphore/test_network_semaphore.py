#!/usr/bin/env python3
# vim: sw=4:ts=4:et:cc=120

import logging
import threading
import time
from unittest.mock import Mock

import pytest

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_NETWORK_SEMAPHORE
from saq.network_semaphore import NetworkSemaphoreServer, NetworkSemaphoreClient
from saq.network_semaphore import client as client_module
from saq.network_semaphore.logging import LoggingSemaphore
from saq.network_semaphore.fallback import (
    get_defined_fallback_semaphore,
    get_undefined_fallback_semaphore,
    get_undefined_fallback_semaphores,
    initialize_fallback_semaphores,
    add_undefined_fallback_semaphore,
)
from saq.network_semaphore.service import NetworkSemaphoreService
from tests.saq.helpers import log_count, wait_for_log_count


def wait_for_condition(predicate, timeout_seconds: float = 10.0, poll_interval_seconds: float = 0.1) -> None:
    """Poll until predicate() returns True or timeout elapses.

    Raises AssertionError on timeout to fail the test.
    """
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(poll_interval_seconds)
    assert False, "Timed out waiting for condition"

@pytest.fixture(autouse=True)
def clear_fallback_semaphores():
    initialize_fallback_semaphores(force=True)

#
# test network semaphores
#

@pytest.mark.unit
def test_add_semaphore():
    server = NetworkSemaphoreServer()
    assert len(server.undefined_semaphores) == 0
    semaphore = server.add_undefined_semaphore("test", 1)
    assert semaphore is not None
    assert isinstance(semaphore, LoggingSemaphore)
    assert len(server.undefined_semaphores) == 1
    assert "test" in server.undefined_semaphores


@pytest.mark.system
def test_service_start_stop():
    service = NetworkSemaphoreService()
    service.start()
    service.wait_for_start(timeout=5)

    service.stop()
    service.wait()

@pytest.mark.system
def test_acquire_release_undefined_network_semaphore():
    server = NetworkSemaphoreServer()
    server.start()
    server.wait_for_start(timeout=5)

    assert len(server.undefined_semaphores) == 0

    client = NetworkSemaphoreClient()
    assert client.acquire("test")
    assert len(server.undefined_semaphores) == 1
    client.release()
    assert not client.semaphore_acquired
    wait_for_condition(lambda: len(server.undefined_semaphores) == 0)

    server.stop()
    server.wait()

    assert log_count("acquiring fallback") == 0


@pytest.mark.system
def test_acquire_release_defined_network_semaphore():
    server = NetworkSemaphoreServer()
    server.config.semaphore_capacity_limits["test"] = 3
    server.start()
    server.wait_for_start(timeout=5)

    assert server.get_semaphore("test") is not None
    assert len(server.undefined_semaphores) == 0

    client = NetworkSemaphoreClient()
    assert client.acquire("test")
    client.release()
    assert not client.semaphore_acquired

    assert len(server.undefined_semaphores) == 0

    server.stop()
    server.wait()

    assert log_count("acquiring fallback") == 0


@pytest.mark.system
def test_acquire_block_network_semaphore():
    server = NetworkSemaphoreServer()
    server.start()
    server.wait_for_start(timeout=5)

    # client_1 grabs the semaphore
    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")

    # client_2 tries to grab the same semaphore with 0 timeout
    client_2 = NetworkSemaphoreClient()
    assert not client_2.acquire("test", 0)

    client_1.release()
    assert client_2.acquire("test", 0)
    client_2.release()

    server.stop()
    server.wait()


@pytest.mark.system
def test_acquire_after_wait_network_semaphore():
    server = NetworkSemaphoreServer()
    server.start()
    server.wait_for_start(timeout=5)

    event_1 = threading.Event()
    event_2 = threading.Event()

    def run_client_1():
        client_1_local = NetworkSemaphoreClient()
        assert client_1_local.acquire("test")
        event_1.set()
        event_2.wait()
        client_1_local.release()

    def run_client_2():
        client_2_local = NetworkSemaphoreClient()
        assert client_2_local.acquire("test")
        client_2_local.release()

    thread_1 = threading.Thread(target=run_client_1)
    thread_1.start()
    event_1.wait()

    thread_2 = threading.Thread(target=run_client_2)
    thread_2.start()
    wait_for_log_count("waiting for semaphore", 1)
    event_2.set()

    thread_2.join()
    thread_1.join()

    server.stop()
    server.wait()


@pytest.mark.system
def test_multiple_locks_network_semaphore():
    server = NetworkSemaphoreServer()
    server.config.semaphore_capacity_limits["test"] = 3
    server.start()
    server.wait_for_start(timeout=5)

    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")
    client_2 = NetworkSemaphoreClient()
    assert client_2.acquire("test")
    client_3 = NetworkSemaphoreClient()
    assert client_3.acquire("test")

    client_4 = NetworkSemaphoreClient()
    assert not client_4.acquire("test", 0)

    client_3.release()
    assert client_4.acquire("test")

    client_4.release()
    client_2.release()
    client_1.release()

    server.stop()
    server.wait()


@pytest.mark.system
def test_cancel_request_callback():
    server = NetworkSemaphoreServer()
    server.start()
    server.wait_for_start(timeout=5)

    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")

    client_2 = NetworkSemaphoreClient(cancel_request_callback=lambda: True)
    assert not client_2.acquire("test")

    client_1.release()

    server.stop()
    server.wait()


#
# test fallback semaphores
#

@pytest.mark.unit
def test_add_undefined_fallback_semaphore():
    initialize_fallback_semaphores()

    assert len(get_undefined_fallback_semaphores()) == 0
    semaphore = add_undefined_fallback_semaphore("test", 1)
    assert semaphore is not None
    assert isinstance(semaphore, LoggingSemaphore)
    assert len(get_undefined_fallback_semaphores()) == 1
    assert get_undefined_fallback_semaphore("test") is not None


@pytest.mark.integration
def test_acquire_release_undefined_fallback_semaphore():
    initialize_fallback_semaphores()

    assert len(get_undefined_fallback_semaphores()) == 0

    client = NetworkSemaphoreClient()
    assert client.acquire("test")
    assert len(get_undefined_fallback_semaphores()) == 1
    client.release()
    assert not client.semaphore_acquired
    wait_for_condition(lambda: len(get_undefined_fallback_semaphores()) == 0)


@pytest.mark.integration
def test_acquire_release_defined_fallback_semaphore():
    get_service_config(SERVICE_NETWORK_SEMAPHORE).semaphore_capacity_limits["test"] = 3
    initialize_fallback_semaphores(force=True)

    assert get_defined_fallback_semaphore("test") is not None
    assert len(get_undefined_fallback_semaphores()) == 0

    client = NetworkSemaphoreClient()
    assert client.acquire("test")
    client.release()
    assert not client.semaphore_acquired

    assert len(get_undefined_fallback_semaphores()) == 0


@pytest.mark.integration
def test_use_fallback_semaphores():
    # make sure what we can use fallback semaphores if network semaphores are unavailable
    client = NetworkSemaphoreClient()
    assert client.fallback_semaphore is None

    assert len(get_undefined_fallback_semaphores()) == 0
    client.acquire("test")
    assert client.fallback_semaphore is not None
    assert client.semaphore_acquired
    assert len(get_undefined_fallback_semaphores()) == 1
    client.release()
    assert len(get_undefined_fallback_semaphores()) == 0
    assert not client.semaphore_acquired


@pytest.mark.integration
def test_fallback_semaphore_timeout():
    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")
    client_2 = NetworkSemaphoreClient()
    assert not client_2.acquire("test", timeout=0)
    client_1.release()


@pytest.mark.integration
def test_acquire_after_wait_fallback_semaphore():
    event_1 = threading.Event()
    event_2 = threading.Event()

    client_1 = NetworkSemaphoreClient()
    client_2 = NetworkSemaphoreClient()

    def run_client_1():
        client_1_local = NetworkSemaphoreClient()
        assert client_1_local.acquire("test")
        event_1.set()
        event_2.wait()
        client_1_local.release()

    def run_client_2():
        assert not client_2.acquire("test", 0)
        event_2.set()
        assert client_2.acquire("test")
        client_2.release()

    thread_1 = threading.Thread(target=run_client_1)
    thread_1.start()
    event_1.wait()

    thread_2 = threading.Thread(target=run_client_2)
    thread_2.start()

    thread_2.join()
    thread_1.join()


@pytest.mark.integration
def test_cancel_request_callback_fallback_semaphore():
    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")

    client_2 = NetworkSemaphoreClient(cancel_request_callback=lambda: True)
    assert not client_2.acquire("test")

    client_1.release()


@pytest.mark.unit
def test_failed_fallback_release_is_reported(monkeypatch):
    client = NetworkSemaphoreClient()
    client.semaphore_name = "test_semaphore"
    client.semaphore_acquired = True
    client.fallback_semaphore = Mock(release=Mock(side_effect=RuntimeError("release failed")))
    client.release_event = threading.Event()
    client.failsafe_thread = Mock()
    monkeypatch.setattr(client_module, "maintain_undefined_semaphores", lambda: None)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    client.release()

    write_error_report.assert_called_once()
    record = write_error_report.call_args.kwargs["record"]
    assert "unable to release fallback semaphore test_semaphore" in record.getMessage()
    # the failsafe thread is still told to exit
    assert client.semaphore_acquired is False
    assert client.release_event.is_set()


@pytest.mark.unit
def test_release_after_a_cancelled_acquire_does_nothing(caplog):
    # the semaphore service is not running, so this goes to the fallback, which is cancelled
    client = NetworkSemaphoreClient(cancel_request_callback=lambda: True)
    assert not client.acquire("test")

    with caplog.at_level(logging.WARNING):
        client.release()

    assert not client.semaphore_acquired
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("release called on unacquired semaphore" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_second_release_does_not_release_the_fallback_again(caplog):
    client = NetworkSemaphoreClient()
    assert client.acquire("test")
    semaphore = client.fallback_semaphore
    client.release()
    value = semaphore._value

    with caplog.at_level(logging.WARNING):
        client.release()

    assert semaphore._value == value
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
