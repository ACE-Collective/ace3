"""Tests for the `ace test` commands."""

import logging
from types import SimpleNamespace

import pytest
import requests

import saq.cli.commands.testing as testing_cli
import saq.database
import saq.modules.adapter
import saq.network_semaphore
import saq.proxy
from saq.cli.cli_main import get_cli_parser
from saq.configuration.schema import ProxyConfig


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["test", *argv])
    with pytest.raises(SystemExit) as e:
        args.func(args)

    return e.value.code


@pytest.fixture
def requests_get(monkeypatch):
    calls = []

    def _get(url, **kwargs):
        calls.append((url, kwargs))
        if "unreachable" in url:
            raise requests.ConnectionError("connection refused")

        return SimpleNamespace(status_code=200, reason="OK")

    monkeypatch.setattr(testing_cli.requests, "get", _get)
    return calls


@pytest.mark.unit
def test_proxy_downloads_through_the_default_proxy(monkeypatch, requests_get):
    monkeypatch.setattr(saq.proxy, "proxies", lambda: {"https": "http://proxy.example.com:3128"})

    assert _ace("proxy", "https://www.example.com/") == 0

    assert requests_get == [("https://www.example.com/", {
        "proxies": {"https": "http://proxy.example.com:3128"}, "verify": False, "timeout": 20})]


@pytest.mark.unit
def test_proxy_without_a_default_proxy_goes_direct(requests_get):
    # no default_proxy is configured in the unit test config
    assert _ace("proxy", "https://www.example.com/") == 0

    assert requests_get[0][1]["proxies"] == {}


@pytest.mark.unit
def test_proxy_failure_is_logged_and_exits_1(requests_get, caplog):
    assert _ace("proxy", "https://unreachable.example.com/") == 1

    [record] = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert record.getMessage().startswith(
        "unable to download https://unreachable.example.com/ through the default proxy: connection refused")
    assert record.exc_info is not None


@pytest.mark.unit
def test_proxies_tests_every_proxy_and_reports_failures(monkeypatch, capsys):
    configs = [ProxyConfig(name=name, transport="http", host=f"{name}.example.com", port=3128)
               for name in ("down", "up")]
    monkeypatch.setattr(testing_cli, "get_config", lambda: SimpleNamespace(proxies=configs))
    monkeypatch.setattr(saq.proxy, "proxies", lambda name: {"https": f"http://{name}.example.com:3128"})

    def _request(self, method, url, **kwargs):
        assert kwargs["timeout"] == 20
        if self.proxies["https"].startswith("http://down."):
            raise requests.ConnectionError("proxy down")

        return SimpleNamespace(status_code=204, reason="No Content")

    monkeypatch.setattr(requests.Session, "request", _request)

    assert _ace("proxies", "https://www.example.com/") == 1

    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("testing proxy down (")
    assert out[1] == "result: FAILED - proxy down"
    assert out[2].startswith("testing proxy up (")
    assert out[3] == "result: (204) - No Content"


@pytest.mark.integration
def test_database_connections(capsys):
    assert _ace("database-connections") == 0

    out = capsys.readouterr().out
    assert out.count("OK") == out.count("trying ") > 0


@pytest.mark.unit
def test_database_connection_failure_exits_1(monkeypatch, capsys):
    def _fail(name):
        raise RuntimeError(f"cannot reach {name}")

    monkeypatch.setattr(saq.database, "get_db_connection", _fail)

    assert _ace("database-connections") == 1
    assert "FAILED: cannot reach " in capsys.readouterr().out


class _FakeSemaphoreClient:
    acquired = True
    released = []

    def acquire(self, name):
        self.name = name
        return self.acquired

    def release(self):
        self.released.append(self.name)


@pytest.fixture
def semaphore_client(monkeypatch):
    _FakeSemaphoreClient.acquired = True
    _FakeSemaphoreClient.released = []
    monkeypatch.setattr(saq.network_semaphore, "NetworkSemaphoreClient", _FakeSemaphoreClient)
    return _FakeSemaphoreClient


@pytest.mark.unit
def test_network_semaphore_acquired_and_released(semaphore_client):
    assert _ace("network-semaphore", "test_sem", "-t", "0") == 0
    assert semaphore_client.released == ["test_sem"]


@pytest.mark.unit
def test_network_semaphore_not_acquired_exits_1(semaphore_client, caplog):
    semaphore_client.acquired = False

    assert _ace("network-semaphore", "test_sem", "-t", "0") == 1
    assert "unable to acquire network semaphore test_sem" in caplog.text
    assert semaphore_client.released == []


class _FakeModule:
    def __init__(self, name):
        self.name = name

    def verify_environment(self):
        if self.name == "broken":
            raise RuntimeError("missing tool")


@pytest.fixture
def modules(monkeypatch):
    configs = [SimpleNamespace(name=name, enabled=name != "disabled")
               for name in ("good", "disabled", "missing", "broken")]
    loaded = []

    def _load(name):
        loaded.append(name)
        return None if name == "missing" else _FakeModule(name)

    monkeypatch.setattr(testing_cli, "get_config", lambda: SimpleNamespace(analysis_modules=configs))
    monkeypatch.setattr(saq.modules.adapter, "load_module_from_config", _load)
    return configs, loaded


@pytest.mark.unit
def test_verify_modules_reports_each_failure(modules, caplog):
    caplog.set_level(logging.INFO)
    configs, loaded = modules

    assert _ace("modules") == 1

    # disabled modules are not loaded; one failure does not stop the rest
    assert loaded == ["good", "missing", "broken"]
    assert "analysis module good verification OK" in caplog.text
    assert "analysis module missing not found" in caplog.text
    [record] = [r for r in caplog.records if "failed environment verification" in r.getMessage()]
    assert record.getMessage() == "analysis module broken failed environment verification: missing tool"
    assert record.exc_info is not None


@pytest.mark.unit
def test_verify_modules_all_ok(modules):
    configs, loaded = modules
    configs[2:] = []

    assert _ace("modules") == 0
