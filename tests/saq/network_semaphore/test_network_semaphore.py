#!/usr/bin/env python3
# vim: sw=4:ts=4:et:cc=120

import logging
import threading
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
from tests.saq.helpers import log_count, wait_for_condition, wait_for_log_count


@pytest.fixture(autouse=True)
def clear_fallback_semaphores():
    initialize_fallback_semaphores(force=True)


@pytest.fixture
def server():
    """A network semaphore server, stopped after the test: a failed assertion would otherwise leave
    its thread running, and the test process waiting for it at exit."""
    server = NetworkSemaphoreServer()
    yield server
    server.stop()
    server.wait()

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
def test_acquire_release_undefined_network_semaphore(server):
    server.start()
    server.wait_for_start(timeout=5)

    assert len(server.undefined_semaphores) == 0

    client = NetworkSemaphoreClient()
    assert client.acquire("test")
    assert len(server.undefined_semaphores) == 1
    client.release()
    assert not client.semaphore_acquired
    wait_for_condition(lambda: len(server.undefined_semaphores) == 0)


    assert log_count("acquiring fallback") == 0


@pytest.mark.system
def test_acquire_release_defined_network_semaphore(server):
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


    assert log_count("acquiring fallback") == 0


@pytest.mark.system
def test_acquire_block_network_semaphore(server):
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

    # the clients reached the server: the fallback refuses a second client the same way
    assert log_count("acquiring fallback") == 0



@pytest.mark.system
def test_acquire_after_wait_network_semaphore(server):
    server.start()
    server.wait_for_start(timeout=5)

    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")

    # an assertion in a thread does not fail the test, so the waiting client's result comes back here
    client_2 = NetworkSemaphoreClient()
    result = []
    thread = threading.Thread(target=lambda: result.append(client_2.acquire("test")), daemon=True)
    thread.start()
    wait_for_log_count("waiting for semaphore", 1)

    client_1.release()
    thread.join(10)
    assert result == [True]
    # it got the network semaphore it waited for, not a fallback
    assert client_2.fallback_semaphore is None
    client_2.release()



@pytest.mark.system
def test_multiple_locks_network_semaphore(server):
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

    # the clients reached the server: the fallback has the same capacity
    assert log_count("acquiring fallback") == 0



@pytest.mark.system
def test_cancel_request_callback(server):
    server.start()
    server.wait_for_start(timeout=5)

    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")

    client_2 = NetworkSemaphoreClient(cancel_request_callback=lambda: True)
    assert not client_2.acquire("test")

    client_1.release()
    # the clients reached the server: a cancelled fallback request returns False too
    assert log_count("acquiring fallback") == 0



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
    assert client.fallback_semaphore is not None
    assert len(get_undefined_fallback_semaphores()) == 1
    client.release()
    assert not client.semaphore_acquired
    assert len(get_undefined_fallback_semaphores()) == 0


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
def test_acquire_after_wait_fallback_semaphore():
    # the semaphore service is not running, so both clients use the fallback
    client_1 = NetworkSemaphoreClient()
    assert client_1.acquire("test")

    client_2 = NetworkSemaphoreClient()
    assert not client_2.acquire("test", 0)

    # an assertion in a thread does not fail the test, so the waiting client's result comes back here
    result = []
    thread = threading.Thread(target=lambda: result.append(client_2.acquire("test")), daemon=True)
    thread.start()
    thread.join(0.5)
    assert thread.is_alive(), "the second client did not wait for the semaphore"

    client_1.release()
    thread.join(10)
    assert result == [True]
    client_2.release()


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
