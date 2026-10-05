"""Tests for `ace gui start --api-v2`, which runs a private API v2 server next to the GUI."""

import os
import socket
import sys
from argparse import Namespace
from unittest.mock import MagicMock

import pytest

from saq.cli.commands import gui_api
from saq.constants import ENV_ACE_LOG_CONFIG_PATH
from saq.environment import get_base_dir


def _gui_args(**kwargs) -> Namespace:
    args = dict(api_v2=True, api_v2_port=None, print_uri_paths=False, logging_config_path=None, address=None, port=None)
    args.update(kwargs)
    return Namespace(**args)


@pytest.fixture
def gui_mocks(monkeypatch):
    """Stubs out everything start_gui would actually start; the proxy settings it leaves in the environment
    are restored afterwards."""
    monkeypatch.delenv("ACE_API_V2_HOST", raising=False)
    monkeypatch.delenv("ACE_API_V2_PORT", raising=False)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)

    mocks = Namespace(
        run_simple=MagicMock(),
        start_api_v2_server=MagicMock(return_value=MagicMock(pid=1234)),
        atexit_register=MagicMock(),
    )
    monkeypatch.setattr("werkzeug.serving.run_simple", mocks.run_simple)
    monkeypatch.setattr("app.create_app", MagicMock())
    monkeypatch.setattr(gui_api, "start_api_v2_server", mocks.start_api_v2_server)
    monkeypatch.setattr(gui_api.atexit, "register", mocks.atexit_register)
    return mocks


@pytest.mark.unit
def test_find_free_port():
    port = gui_api.find_free_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))


@pytest.mark.unit
@pytest.mark.parametrize("logging_config_path", [None, "etc/logging_configs/debug_logging.yaml"])
def test_start_api_v2_server(monkeypatch, logging_config_path):
    monkeypatch.delenv(ENV_ACE_LOG_CONFIG_PATH, raising=False)
    popen = MagicMock()
    monkeypatch.setattr(gui_api.subprocess, "Popen", popen)

    gui_api.start_api_v2_server(24555, logging_config_path)

    command = popen.call_args.args[0]
    kwargs = popen.call_args.kwargs
    assert command[:4] == [sys.executable, "-m", "uvicorn", "api_uvicorn:application"]
    assert command[command.index("--host") + 1] == "127.0.0.1"
    assert command[command.index("--port") + 1] == "24555"
    assert "--reload" in command
    assert kwargs["cwd"] == get_base_dir()
    assert kwargs["preexec_fn"] is gui_api._terminate_with_parent
    assert kwargs["env"].get(ENV_ACE_LOG_CONFIG_PATH) == logging_config_path


@pytest.mark.unit
def test_start_gui_starts_api_v2(gui_mocks):
    gui_api.start_gui(_gui_args(api_v2_port=24556))

    gui_mocks.start_api_v2_server.assert_called_once_with(24556, None)
    gui_mocks.atexit_register.assert_called_once_with(gui_api.stop_api_v2_server,
                                                      gui_mocks.start_api_v2_server.return_value)
    assert os.environ["ACE_API_V2_HOST"] == "127.0.0.1"
    assert os.environ["ACE_API_V2_PORT"] == "24556"
    gui_mocks.run_simple.assert_called_once()


@pytest.mark.unit
def test_start_gui_reloader_child_does_not_start_api_v2(gui_mocks, monkeypatch):
    # the reloader child inherits the proxy settings from the outer process
    monkeypatch.setenv("WERKZEUG_RUN_MAIN", "true")
    monkeypatch.setenv("ACE_API_V2_HOST", "127.0.0.1")
    monkeypatch.setenv("ACE_API_V2_PORT", "24557")

    gui_api.start_gui(_gui_args())

    gui_mocks.start_api_v2_server.assert_not_called()
    assert os.environ["ACE_API_V2_PORT"] == "24557"
    gui_mocks.run_simple.assert_called_once()


@pytest.mark.unit
def test_start_gui_without_api_v2(gui_mocks):
    gui_api.start_gui(_gui_args(api_v2=False))

    gui_mocks.start_api_v2_server.assert_not_called()
    assert "ACE_API_V2_PORT" not in os.environ


@pytest.mark.unit
def test_stop_api_v2_server():
    process = MagicMock()
    process.poll.return_value = None
    gui_api.stop_api_v2_server(process)
    process.terminate.assert_called_once()
    process.wait.assert_called_once()

    exited = MagicMock()
    exited.poll.return_value = 0
    gui_api.stop_api_v2_server(exited)
    exited.terminate.assert_not_called()
