import os
import signal
import subprocess
import sys

import pytest

from saq.database.model import hash_password
from saq.environment import get_base_dir
from tests import unittest_session
from tests.saq.helpers import WaitTimedOutError, process_is_gone, wait_for_condition

# a pytest process reduced to what matters here: it starts the log collector, reports the pid of
# the collector's server and then waits to be killed
_START_LOG_COLLECTOR = """
from tests.saq import helpers
helpers.initialize_unittest_logging()
print(helpers.test_log_manager._process.pid, flush=True)
import time
time.sleep(120)
"""


@pytest.mark.unit
def test_log_collector_exits_when_its_process_is_killed():
    # the OOM killer SIGKILLs a pytest worker, and no finalizer of the worker ever runs
    worker = subprocess.Popen(
        [sys.executable, "-c", _START_LOG_COLLECTOR],
        cwd=get_base_dir(),
        stdout=subprocess.PIPE,
        text=True,
    )
    server_pid = None
    try:
        server_pid = int(worker.stdout.readline())
        assert not process_is_gone(server_pid)
        os.kill(worker.pid, signal.SIGKILL)
        worker.wait(timeout=10)

        wait_for_condition(lambda: process_is_gone(server_pid), timeout=10)
    except WaitTimedOutError:
        pytest.fail(f"the log collector's server (pid {server_pid}) outlived the process that started it")
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=10)
        if server_pid is not None and not process_is_gone(server_pid):
            os.kill(server_pid, signal.SIGKILL)


@pytest.mark.unit
def test_exit_with_a_process_that_already_exited():
    exited = subprocess.Popen([sys.executable, "-c", "pass"])
    exited.wait(timeout=10)

    # a pid nothing has right now: the process was reaped above
    result = subprocess.run(
        [sys.executable, "-c", f"from tests import unittest_session; unittest_session.exit_with({exited.pid}); import time; time.sleep(30)"],
        cwd=get_base_dir(),
        timeout=10,
    )
    assert result.returncode == 1


@pytest.mark.unit
def test_each_checkout_gets_its_own_data_dir_outside_it(tmp_path, monkeypatch):
    # the checkout is a bind mount in the dev container, where the suite's file operations are
    # slow, so the slots' data directories live in the container's own filesystem instead
    checkout_a, checkout_b = tmp_path / "a", tmp_path / "b"
    checkout_a.mkdir()
    checkout_b.mkdir()
    (tmp_path / "link").symlink_to(checkout_a)

    roots = {}
    for name in ("a", "b", "link"):
        monkeypatch.setenv("SAQ_HOME", str(tmp_path / name))
        roots[name] = unittest_session.get_data_dir_root()

    assert roots["a"] != roots["b"]
    assert roots["link"] == roots["a"]
    for root in roots.values():
        assert os.path.dirname(root) == unittest_session.DATA_DIR_BASE
        assert not root.startswith(str(tmp_path))

    monkeypatch.setenv("SAQ_HOME", str(checkout_a))
    overrides = unittest_session.session_overrides()
    data_dir = unittest_session.get_session_data_dir()
    assert os.path.dirname(data_dir) == roots["a"]
    assert overrides["global"]["data_dir"] == data_dir
    assert overrides["storage"]["base_dir"] == os.path.join(data_dir, "storage")
    assert overrides["service_network_semaphore"]["stats_dir"] == os.path.join(data_dir, "var", "network_semaphore")


@pytest.mark.unit
def test_a_slot_takes_its_ports_from_the_run_port_block(monkeypatch):
    monkeypatch.setenv(unittest_session.PORT_BLOCK_ENV_VAR, "3")
    monkeypatch.setenv(unittest_session.WORKER_ENV_VAR, "gw2")
    offset = 3 * unittest_session.PORT_BLOCK_SIZE + 2

    overrides = unittest_session.session_overrides()
    assert overrides["api"]["listen_port"] == unittest_session.API_BASE_PORT + offset
    assert overrides["api"]["prefix"] == f"localhost:{unittest_session.API_BASE_PORT + offset}"
    assert overrides["service_network_semaphore"]["bind_port"] == unittest_session.NETWORK_SEMAPHORE_BASE_PORT + offset
    assert overrides["service_network_semaphore"]["remote_port"] == unittest_session.NETWORK_SEMAPHORE_BASE_PORT + offset


@pytest.mark.unit
def test_a_slot_past_the_port_block_is_refused(monkeypatch):
    # it would take the first port of the next block, another run's
    monkeypatch.setenv(unittest_session.PORT_BLOCK_ENV_VAR, "3")
    monkeypatch.setenv(unittest_session.WORKER_ENV_VAR, f"gw{unittest_session.PORT_BLOCK_SIZE}")
    with pytest.raises(ValueError, match="at most 64 xdist workers"):
        unittest_session.get_api_port()


@pytest.mark.unit
def test_ports_without_a_claimed_port_block_are_refused(monkeypatch):
    monkeypatch.delenv(unittest_session.PORT_BLOCK_ENV_VAR)
    with pytest.raises(RuntimeError, match=unittest_session.PORT_BLOCK_ENV_VAR):
        unittest_session.session_overrides()


@pytest.mark.unit
def test_each_checkout_gets_its_own_qdrant_collections(tmp_path, monkeypatch):
    # the stack's Qdrant is shared by every checkout's runs
    monkeypatch.setenv(unittest_session.WORKER_ENV_VAR, "gw1")
    prefixes = {}
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        monkeypatch.setenv("SAQ_HOME", str(tmp_path / name))
        prefixes[name] = unittest_session.session_overrides()["qdrant"]["collection_prefix"]

    assert prefixes["a"] != prefixes["b"]
    for prefix in prefixes.values():
        assert prefix.startswith("ace3-alerts-unittest-")
        assert prefix.endswith("-gw1")


@pytest.mark.unit
def test_passwords_are_hashed_at_bcrypt_cost_4_in_the_tests():
    # tests/conftest.py lowers the cost: at production's 12, each test user and each login
    # cost about 180 ms
    assert hash_password("password").startswith("$2b$04$")
