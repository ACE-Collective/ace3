"""Tests for `ace gui start --api-v2`, which runs a private API v2 server next to the GUI."""

import io
import json
import os
import signal
import socket
import subprocess
import sys
import threading
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    process = subprocess.Popen(["sleep", "60"])
    try:
        gui_api.stop_api_v2_server(process)
        assert process.poll() == -signal.SIGTERM
    finally:
        process.kill()
        process.wait(timeout=10)

    # an already exited server is left alone
    exited = subprocess.Popen(["true"])
    exited.wait(timeout=10)
    gui_api.stop_api_v2_server(exited)
    assert exited.returncode == 0


@pytest.mark.unit
def test_stop_api_v2_server_kills_a_server_that_will_not_stop():
    process = MagicMock()
    process.poll.return_value = None
    process.wait.side_effect = subprocess.TimeoutExpired("uvicorn", 10)

    gui_api.stop_api_v2_server(process)

    process.terminate.assert_called_once()
    process.wait.assert_called_once_with(timeout=10)
    process.kill.assert_called_once()


@pytest.mark.unit
def test_start_gui_print_uri_paths(gui_mocks, monkeypatch, capsys):
    app = MagicMock()
    app.url_map.iter_rules.return_value = ["/ace/", "/ace/manage"]
    monkeypatch.setattr("app.create_app", lambda: app)

    with pytest.raises(SystemExit) as excinfo:
        gui_api.start_gui(_gui_args(print_uri_paths=True))

    assert excinfo.value.code == 0
    assert capsys.readouterr().out == "/ace/\n/ace/manage\n"
    # printing the paths starts nothing
    gui_mocks.start_api_v2_server.assert_not_called()
    gui_mocks.run_simple.assert_not_called()


@pytest.mark.unit
def test_start_gui_serves_unknown_paths_as_not_found(gui_mocks, monkeypatch):
    app = MagicMock()
    monkeypatch.setattr("app.create_app", lambda: app)
    gui_api.start_gui(_gui_args(api_v2=False))

    responses = []
    body = app.wsgi_app({"PATH_INFO": "/elsewhere", "REQUEST_METHOD": "GET", "SERVER_NAME": "localhost",
                         "SERVER_PORT": "5000", "wsgi.url_scheme": "https"},
                        lambda status, headers: responses.append(status))
    assert responses == ["404 NOT FOUND"]
    assert b"".join(body) == b"unknown page"


#
# the /api/v2 proxy
#

class _Upstream(BaseHTTPRequestHandler):
    """Answers every request with what it received, as JSON; /missing answers 404."""

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        received = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": self.rfile.read(length).decode() if length else None,
        }
        status = 404 if self.path.startswith("/missing") else 200
        payload = json.dumps(received).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Upstream", "yes")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_DELETE = _answer

    def log_message(self, *args):
        # keeps the test output clean; the request is in the response
        pass


@pytest.fixture
def upstream(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("ACE_API_V2_HOST", "127.0.0.1")
    monkeypatch.setenv("ACE_API_V2_PORT", str(server.server_address[1]))
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=10)


def _call(app, **environ):
    responses = []
    environ.setdefault("REQUEST_METHOD", "GET")
    body = app(environ, lambda status, headers: responses.append((status, dict(headers))))
    [(status, headers)] = responses
    return status, headers, b"".join(body)


@pytest.mark.unit
def test_proxy_forwards_the_request(upstream):
    proxy = gui_api.create_api_v2_proxy()
    payload = b'{"disposition": "FALSE_POSITIVE"}'

    status, headers, body = _call(
        proxy, REQUEST_METHOD="POST", PATH_INFO="/alerts/disposition", QUERY_STRING="a=1&b=2",
        CONTENT_TYPE="application/json", CONTENT_LENGTH=str(len(payload)), **{"wsgi.input": io.BytesIO(payload)},
        HTTP_HOST="localhost:5000", HTTP_ORIGIN="https://localhost:5000", HTTP_SEC_FETCH_SITE="same-origin",
        HTTP_AUTHORIZATION="Bearer token", HTTP_X_ACE_AUTH="api-key", HTTP_COOKIE="session=abc",
        HTTP_CONNECTION="keep-alive", HTTP_TE="trailers", HTTP_UPGRADE="websocket")

    assert status == "200 OK"
    assert headers["X-Upstream"] == "yes"
    received = json.loads(body)
    assert received["method"] == "POST"
    assert received["path"] == "/alerts/disposition?a=1&b=2"
    assert received["body"] == payload.decode()
    sent = received["headers"]
    # what the API decides authentication and same-origin writes on
    assert sent["origin"] == "https://localhost:5000"
    assert sent["sec-fetch-site"] == "same-origin"
    assert sent["authorization"] == "Bearer token"
    assert sent["x-ace-auth"] == "api-key"
    assert sent["cookie"] == "session=abc"
    assert sent["content-type"] == "application/json"
    assert sent["x-forwarded-host"] == "localhost:5000"
    # hop-by-hop headers are per connection, and the host is the upstream's
    assert sent["host"] == f"127.0.0.1:{upstream.server_address[1]}"
    assert "te" not in sent and "upgrade" not in sent
    assert sent.get("connection") != "keep-alive"


@pytest.mark.unit
def test_proxy_passes_an_error_response_through(upstream):
    status, headers, body = _call(gui_api.create_api_v2_proxy(), PATH_INFO="/missing")

    assert status == "404 Not Found"
    assert headers["X-Upstream"] == "yes"
    assert json.loads(body)["path"] == "/missing"


@pytest.mark.unit
def test_proxy_ignores_an_unreadable_body(upstream):
    status, _, body = _call(gui_api.create_api_v2_proxy(), REQUEST_METHOD="POST", PATH_INFO="/x",
                            CONTENT_LENGTH="not a number", **{"wsgi.input": io.BytesIO(b"ignored")})

    assert status == "200 OK"
    assert json.loads(body)["body"] is None


@pytest.mark.unit
def test_proxy_answers_502_when_the_api_is_down(monkeypatch):
    monkeypatch.setenv("ACE_API_V2_HOST", "127.0.0.1")
    monkeypatch.setenv("ACE_API_V2_PORT", str(gui_api.find_free_port()))

    status, headers, body = _call(gui_api.create_api_v2_proxy(), PATH_INFO="/x")

    assert status == "502 Bad Gateway"
    assert headers == {"Content-Type": "text/plain"}
    assert body.startswith(b"API v2 proxy error: ")
