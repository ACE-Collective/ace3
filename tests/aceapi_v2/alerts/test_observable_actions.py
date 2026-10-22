"""The alert page's observable actions that ask for analysis (POST
/api/v2/alerts/{alert_uuid}/observables/{observable_uuid}/{collect-file,render,crawl,check-for-clickers})
and the Splunk clicker searches (GET .../clicker-searches)."""

import logging
import uuid
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import AsyncClient

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config, get_splunk_config
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    DIRECTIVE_CLICKER_DETECTION,
    DIRECTIVE_COLLECT_FILE,
    DIRECTIVE_CRAWL,
    DIRECTIVE_RENDER,
    DISPOSITION_SIMULATED,
    F_FILE_LOCATION,
    F_FQDN,
    F_URL,
    STATE_ANALYST_REQUESTED_ANALYSIS,
)
from saq.database.model import Alert, Workload
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.database.util.locking import acquire_lock, release_lock
from saq.modules.test import CustomReqFalseAnalysis, DeclaredNoProduceAnalysis
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

WRITES = ("collect-file", "render", "crawl", "check-for-clickers")


def _path(alert_uuid: str, observable_uuid: str, action: str) -> str:
    return f"/alerts/{alert_uuid}/observables/{observable_uuid}/{action}"


@pytest.fixture
def alert(tmpdir):
    """An alert, dispositioned and in dispositioned mode as an alert an analyst has worked is,
    holding one observable of each type the actions apply to."""
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode="dispositioned")
    root.initialize_storage()
    target = tmpdir / "landing.html"
    target.write_text("<html></html>", encoding="utf8")
    observables = SimpleNamespace(
        file=root.add_file_observable(str(target)),
        file_location=root.add_observable_by_spec(F_FILE_LOCATION, "laptop@C:\\Users\\a\\invoice.exe"),
        url=root.add_observable_by_spec(F_URL, "https://evil.example/login"),
        fqdn=root.add_observable_by_spec(F_FQDN, "evil.example"),
    )
    root.save()
    ALERT(root)
    db = get_db()
    db.query(Alert).filter(Alert.uuid == root.uuid).update({"disposition": "FALSE_POSITIVE"})
    db.commit()
    return SimpleNamespace(uuid=root.uuid, storage_dir=root.storage_dir, observables=observables)


def _queued(alert) -> bool:
    get_db().expire_all()
    return get_db().query(Workload).filter(Workload.uuid == alert.uuid).count() == 1


class TestAccess:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", WRITES)
    async def test_requires_auth(self, unauth_client: AsyncClient, action):
        assert (await unauth_client.post(_path(str(uuid.uuid4()), str(uuid.uuid4()), action))).status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", WRITES)
    async def test_writes_require_observable_write(self, noperm_client: AsyncClient, action):
        assert (await noperm_client.post(_path(str(uuid.uuid4()), str(uuid.uuid4()), action))).status_code == 403

    @pytest.mark.asyncio
    async def test_clicker_searches_require_observable_read(self, noperm_client: AsyncClient):
        response = await noperm_client.get(_path(str(uuid.uuid4()), str(uuid.uuid4()), "clicker-searches"))
        assert response.status_code == 403


class TestRequests:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("action, observable, directive, audited", [
        ("collect-file", "file_location", DIRECTIVE_COLLECT_FILE, "file collection"),
        ("render", "file", DIRECTIVE_RENDER, "a render"),
        ("crawl", "url", DIRECTIVE_CRAWL, "a crawl"),
        ("check-for-clickers", "url", DIRECTIVE_CLICKER_DETECTION, "a clicker check"),
        ("check-for-clickers", "fqdn", DIRECTIVE_CLICKER_DETECTION, "a clicker check"),
    ])
    async def test_adds_the_directive_and_queues_the_alert(self, client: AsyncClient, alert, action, observable,
                                                           directive, audited, caplog: pytest.LogCaptureFixture):
        """Even on a dispositioned alert: the requested analysis runs in correlation mode and gets
        past the stop on dispositioned alerts (Collect File used to queue it in dispositioned
        mode, where no module runs)."""
        caplog.set_level(logging.INFO, logger="aceapi_v2.alerts.router")
        target = getattr(alert.observables, observable)

        response = await client.post(_path(alert.uuid, target.uuid, action))

        assert response.status_code == 202, response.text
        root = load_root(alert.storage_dir)
        assert root.get_observable(target.uuid).has_directive(directive)
        assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
        assert root.state.get(STATE_ANALYST_REQUESTED_ANALYSIS) is True
        assert _queued(alert)
        assert any(message.startswith(f"AUDIT: user unittest requested {audited} for observable")
                   and message.endswith(f"in alert {alert.uuid}") for message in caplog.messages)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action, observable", [
        ("collect-file", "file"),
        ("render", "url"),
        ("crawl", "fqdn"),
        ("check-for-clickers", "file_location"),
    ])
    async def test_an_observable_of_another_type(self, client: AsyncClient, alert, action, observable):
        response = await client.post(_path(alert.uuid, getattr(alert.observables, observable).uuid, action))

        assert response.status_code == 422
        assert not _queued(alert)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", WRITES)
    async def test_unknown_alert_or_observable(self, client: AsyncClient, alert, action):
        assert (await client.post(_path("not-a-uuid", alert.observables.url.uuid, action))).status_code == 400
        assert (await client.post(_path(str(uuid.uuid4()), alert.observables.url.uuid, action))).status_code == 404
        assert (await client.post(_path(alert.uuid, str(uuid.uuid4()), action))).status_code == 404

    @pytest.mark.asyncio
    async def test_a_locked_alert_is_a_conflict(self, client: AsyncClient, alert):
        """The engine holds the lock while it analyzes; the analyst tries again."""
        engine_lock = str(uuid.uuid4())
        assert acquire_lock(alert.uuid, engine_lock)
        try:
            response = await client.post(_path(alert.uuid, alert.observables.url.uuid, "crawl"))
        finally:
            release_lock(alert.uuid, engine_lock)

        assert response.status_code == 409
        assert "being analyzed" in response.json()["detail"]
        assert not load_root(alert.storage_dir).get_observable(alert.observables.url.uuid).has_directive(DIRECTIVE_CRAWL)
        assert not _queued(alert)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action, observable, directive", [
        ("collect-file", "file_location", DIRECTIVE_COLLECT_FILE),
        ("render", "file", DIRECTIVE_RENDER),
        ("crawl", "url", DIRECTIVE_CRAWL),
        ("check-for-clickers", "url", DIRECTIVE_CLICKER_DETECTION),
    ])
    async def test_a_simulated_alert_is_never_reanalyzed(self, client: AsyncClient, alert, action, observable,
                                                         directive):
        """A SIMULATED (test-run) alert's tree stays as its run review froze it (docs/SVS_RUNS.md)."""
        db = get_db()
        db.query(Alert).filter(Alert.uuid == alert.uuid).update({"disposition": DISPOSITION_SIMULATED})
        db.commit()
        target = getattr(alert.observables, observable)

        response = await client.post(_path(alert.uuid, target.uuid, action))

        assert response.status_code == 409
        assert response.json()["detail"].startswith(f"alert {alert.uuid} is SIMULATED")
        assert not load_root(alert.storage_dir).get_observable(target.uuid).has_directive(directive)
        assert not _queued(alert)

    @pytest.mark.asyncio
    async def test_the_lock_is_released(self, client: AsyncClient, alert):
        assert (await client.post(_path(alert.uuid, alert.observables.url.uuid, "crawl"))).status_code == 202

        assert (await client.post(_path(alert.uuid, alert.observables.fqdn.uuid, "check-for-clickers"))).status_code == 202

    @pytest.mark.asyncio
    async def test_a_clicker_check_replaces_earlier_clicker_results(self, client: AsyncClient, alert):
        """The engine skips a module whose analysis exists, so a repeat check drops the earlier
        clicker analyses; other analyses stay."""
        root = load_root(alert.storage_dir)
        url = root.get_observable(alert.observables.url.uuid)
        url.add_analysis(DeclaredNoProduceAnalysis())
        url.add_analysis(CustomReqFalseAnalysis())
        root.save()

        # DeclaredNoProduceAnalysis stands in for a clicker provider's analysis
        with patch("aceapi_v2.alerts.service.REGISTERED_CLICKER_PROVIDERS", [DeclaredNoProduceAnalysis]):
            response = await client.post(_path(alert.uuid, alert.observables.url.uuid, "check-for-clickers"))

        assert response.status_code == 202
        url = load_root(alert.storage_dir).get_observable(alert.observables.url.uuid)
        assert [type(analysis) for analysis in url.all_analysis] == [CustomReqFalseAnalysis]


class TestClickerSearches:
    @pytest.mark.asyncio
    async def test_the_searches_for_the_observable(self, client: AsyncClient, alert, tmp_path, monkeypatch):
        clicker_config = tmp_path / "clicker_detection.yaml"
        clicker_config.write_text(
            "splunk:\n"
            "  enabled: true\n"
            "  searches:\n"
            "    proxy:\n"
            "      observable_types: [url]\n"
            "      query: 'index=proxy <O_VALUE>'\n"
            "    hosts_only:\n"
            "      observable_types: [fqdn]\n"
            "      query: 'index=dns <O_VALUE>'\n"
        )
        monkeypatch.setattr(get_analysis_module_config("clicker_detection_splunk"), "config_path", str(clicker_config))

        response = await client.get(_path(alert.uuid, alert.observables.url.uuid, "clicker-searches"))

        assert response.status_code == 200
        data = response.json()["data"]
        assert [search["name"] for search in data] == ["proxy"]
        url = urlparse(data[0]["url"])
        assert url.scheme == "https"
        assert url.hostname == get_splunk_config("default").host
        assert '"https://evil.example/login"' in parse_qs(url.query)["q"][0]

    @pytest.mark.asyncio
    async def test_none_when_the_splunk_module_is_not_configured(self, client: AsyncClient, alert):
        with patch("aceapi_v2.alerts.service.get_analysis_module_config", side_effect=ValueError("not configured")):
            response = await client.get(_path(alert.uuid, alert.observables.url.uuid, "clicker-searches"))

        assert response.status_code == 200
        assert response.json()["data"] == []

    @pytest.mark.asyncio
    async def test_unknown_observable(self, client: AsyncClient, alert):
        assert (await client.get(_path(alert.uuid, str(uuid.uuid4()), "clicker-searches"))).status_code == 404
