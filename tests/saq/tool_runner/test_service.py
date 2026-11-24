import datetime
import os
import shutil
import tempfile
import threading

import pytest

from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import SandboxConfig
from saq.constants import SERVICE_TOOL_RUNNER
from saq.sandbox.runner import sandbox_python
from saq.tool_runner import service as service_module
from saq.tool_runner.client import get_socket_path, run_on_runner
from saq.tool_runner.service import ToolRunnerService, ToolRunnerServiceConfig
from tests.saq.helpers import wait_for_condition


@pytest.fixture
def socket_dir(monkeypatch):
    # a short path: a unix socket's is limited to 108 bytes
    path = tempfile.mkdtemp(prefix="tool-runner-", dir="/tmp")
    monkeypatch.setattr(get_config().get_service_config(SERVICE_TOOL_RUNNER), "socket_dir", path)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _echo(tmp_path) -> str:
    return run_on_runner([sandbox_python(), "-I", "-c", "print('served')"], env={"PATH": "/usr/bin:/bin"},
                         cwd=str(tmp_path), workdir=str(tmp_path), timeout=datetime.timedelta(seconds=30),
                         config=SandboxConfig()).stdout


@pytest.mark.unit
def test_the_default_configuration():
    config = get_service_config(SERVICE_TOOL_RUNNER)

    assert isinstance(config, ToolRunnerServiceConfig)
    assert config.python_module == "saq.tool_runner.service"
    assert config.enabled


@pytest.mark.unit
def test_the_service_serves_the_configured_socket(socket_dir, tmp_path):
    service = ToolRunnerService()
    service.start()
    try:
        assert service.wait_for_start(5)
        assert get_socket_path() == os.path.join(socket_dir, "runner.sock")
        assert _echo(tmp_path) == "served\n"
    finally:
        service.stop()
        service.wait()

    assert not os.path.exists(get_socket_path())


class _Coordinator:
    def __init__(self):
        self.requested = threading.Event()

    def wait_for_shutdown(self, timeout):
        return self.requested.wait(timeout)


@pytest.mark.unit
def test_single_threaded_it_serves_until_a_shutdown_is_requested(socket_dir, tmp_path, monkeypatch):
    coordinator = _Coordinator()
    monkeypatch.setattr(service_module, "get_shutdown_coordinator", lambda: coordinator)
    service = ToolRunnerService()
    thread = threading.Thread(target=service.start_single_threaded, daemon=True)
    thread.start()

    wait_for_condition(lambda: os.path.exists(get_socket_path()), timeout=10)
    assert _echo(tmp_path) == "served\n"
    assert thread.is_alive()

    coordinator.requested.set()
    thread.join(30)
    assert not thread.is_alive()
    assert not os.path.exists(get_socket_path())
