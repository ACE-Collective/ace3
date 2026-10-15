"""The AI app's export routes: ai:export gating, the alert pages (archived alerts included, with
their observables, detections and events), the observable lookup, audit lines and the limiter."""

import json

import pytest
import pytest_asyncio

import aceapi_ai.export.service as export_service
from aceapi_ai.export.schemas import MAX_OBSERVABLE_IDS
from aceapi_ai.ratelimit import RateLimitExceeded, rate_limiter
from aceapi_v2.alerts import service as alerts_service
from saq.configuration.config import get_config
from saq.database.model import Alert, Comment, EventMapping
from saq.database.pool import get_db
from tests.aceapi_ai.conftest import api_key_client
from tests.aceapi_ai.test_events import _make_event
from tests.aceapi_v2.conftest import make_api_key
from tests.saq.helpers import insert_alert, insert_alert_with_detections

pytestmark = pytest.mark.integration

SIGNATURE_UUID = "6f0e6a8e-3b5c-4f8e-9a51-0c1d2e3f4a5b"


@pytest_asyncio.fixture
async def export_client(_override_db_session, session, test_user):
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "export")])
    async with api_key_client(key) as client:
        yield client


@pytest.fixture
def no_settle(monkeypatch):
    """Lets changed_since return rows changed a moment ago (the settle window is the listing's,
    tested with GET /api/v2/alerts)."""
    monkeypatch.setattr(alerts_service, "CHANGED_SINCE_SETTLE_SECONDS", 0)


def _set(alert: Alert, **values) -> None:
    db = get_db()
    db.execute(Alert.__table__.update().where(Alert.id == alert.id).values(**values))
    db.commit()


async def _all_alerts(client, params: dict, limit: int) -> list[dict]:
    rows = []
    cursor = None
    for _ in range(100):
        page_params = dict(params, limit=limit)
        if cursor:
            page_params["cursor"] = cursor
        response = await client.get("/export/alerts", params=page_params)
        assert response.status_code == 200, response.text
        body = response.json()
        rows.extend(body["data"])
        cursor = body["next_cursor"]
        if cursor is None:
            return rows
    raise AssertionError("pagination did not terminate")


def _audit_events(caplog) -> list[dict]:
    return [json.loads(r.message.removeprefix("AI_AUDIT ")) for r in caplog.records if r.name == "ace.ai_audit"]


@pytest.mark.asyncio
async def test_export_requires_auth(unauth_client):
    assert (await unauth_client.get("/export/alerts")).status_code == 401
    assert (await unauth_client.post("/export/observables", json={"ids": [1]})).status_code == 401


@pytest.mark.asyncio
async def test_export_requires_ai_export_scope(_override_db_session, session, test_user):
    """Every other ai: minor together does not reach the export."""
    key = await make_api_key(session, test_user.id, inherit=False,
                             scope=[("ai", "fake"), ("ai", "alert"), ("ai", "event"), ("ai", "search")])
    async with api_key_client(key) as client:
        assert (await client.get("/export/alerts")).status_code == 403
        assert (await client.post("/export/observables", json={"ids": [1]})).status_code == 403


@pytest.mark.asyncio
async def test_alert_carries_observables_detections_and_events(export_client):
    alert = insert_alert_with_detections(
        [{"description": "bad domain", "signature_uuid": SIGNATURE_UUID, "fqdn": "evil.example.com"}],
        disposition="DELIVERY")
    event = _make_event("export test")
    db = get_db()
    db.add(EventMapping(event_id=event.id, alert_id=alert.id))
    db.commit()

    rows = [row for row in await _all_alerts(export_client, {}, limit=100) if row["uuid"] == alert.uuid]
    assert len(rows) == 1
    row = rows[0]
    assert row["disposition"] == "DELIVERY"
    assert row["disposition_class"] == "tp"
    assert row["disposition_review"] == "UNREVIEWED"
    assert row["event_ids"] == [event.id]
    assert row["observable_ids"]

    (detection,) = row["detections"]
    assert detection["signature_uuid"] == SIGNATURE_UUID
    assert detection["node_kind"] == "observable"
    assert detection["node_type"] == "fqdn"

    response = await export_client.post("/export/observables", json={"ids": row["observable_ids"]})
    assert response.status_code == 200, response.text
    observables = response.json()["data"]
    assert [o["id"] for o in observables] == sorted(row["observable_ids"])

    # the detection's node resolves to one of the alert's observables by (type, sha256)
    (fqdn,) = [o for o in observables if o["type"] == "fqdn"]
    assert fqdn["value"] == "evil.example.com"
    assert fqdn["sha256"] == detection["node_value_sha256"]


@pytest.mark.asyncio
async def test_archived_alert_is_exported_with_its_observables(export_client):
    """The alert reads return 410 for an archived alert; the export reads the database, which
    archiving leaves in place."""
    alert = insert_alert_with_detections(
        [{"description": "bad domain", "signature_uuid": SIGNATURE_UUID, "fqdn": "old.example.com"}],
        disposition="FALSE_POSITIVE")
    _set(alert, archived=True)

    (row,) = [row for row in await _all_alerts(export_client, {}, limit=100) if row["uuid"] == alert.uuid]
    assert row["archived"] is True
    assert row["disposition_class"] == "fp"
    assert row["observable_ids"]


@pytest.mark.asyncio
async def test_alert_comments_are_not_exported(export_client):
    """GET /api/v2/alerts rows carry the analysts' comments; this export's rows do not, so the
    ai:export scope does not hand out analyst-written text."""
    alert = insert_alert()
    db = get_db()
    db.add(Comment(uuid=alert.uuid, user_id=get_config().global_settings.automation_user_id,
                   comment="an analyst's note"))
    db.commit()

    (row,) = [row for row in await _all_alerts(export_client, {}, limit=100) if row["uuid"] == alert.uuid]
    assert "comments" not in row


@pytest.mark.asyncio
async def test_unclassified_disposition_has_no_class(export_client):
    alert = insert_alert()

    (row,) = [row for row in await _all_alerts(export_client, {}, limit=100) if row["uuid"] == alert.uuid]
    assert row["disposition_class"] is None


@pytest.mark.asyncio
async def test_pages_cover_every_alert_once(export_client, no_settle):
    alerts = [insert_alert() for _ in range(3)]
    expected = {alert.uuid for alert in alerts}

    by_id = [row["uuid"] for row in await _all_alerts(export_client, {}, limit=1) if row["uuid"] in expected]
    assert sorted(by_id) == sorted(expected)

    changed = [row["uuid"] for row in await _all_alerts(export_client, {"changed_since": "2020-01-01T00:00:00Z"}, limit=1)
               if row["uuid"] in expected]
    assert sorted(changed) == sorted(expected)


@pytest.mark.asyncio
async def test_malformed_cursor_is_400_and_audited(export_client, caplog):
    with caplog.at_level("INFO", logger="ace.ai_audit"):
        response = await export_client.get("/export/alerts", params={"cursor": "not-a-cursor"})

    assert response.status_code == 400
    (event,) = _audit_events(caplog)
    assert event["event"] == "export_alerts_error" and event["status"] == 400


@pytest.mark.asyncio
async def test_alert_page_is_audited(export_client, caplog):
    insert_alert()
    with caplog.at_level("INFO", logger="ace.ai_audit"):
        response = await export_client.get("/export/alerts", params={"limit": 10})

    assert response.status_code == 200, response.text
    (event,) = _audit_events(caplog)
    assert event["event"] == "export_alerts"
    assert event["limit"] == 10
    assert event["result_count"] == len(response.json()["data"])
    assert event["status"] == 200


@pytest.mark.asyncio
async def test_observable_lookup_bounds_and_unknown_ids(export_client, caplog):
    with caplog.at_level("INFO", logger="ace.ai_audit"):
        response = await export_client.post("/export/observables", json={"ids": [2_000_000_000]})

    assert response.status_code == 200, response.text
    assert response.json()["data"] == []
    (event,) = _audit_events(caplog)
    assert event["event"] == "export_observables" and event["id_count"] == 1 and event["result_count"] == 0

    assert (await export_client.post("/export/observables", json={"ids": []})).status_code == 422
    too_many = list(range(1, MAX_OBSERVABLE_IDS + 2))
    assert (await export_client.post("/export/observables", json={"ids": too_many})).status_code == 422


@pytest.mark.asyncio
async def test_rate_limited_export_is_429_in_its_own_bucket(export_client, monkeypatch, caplog):
    def refuse(backend_name, limits):
        assert backend_name == export_service.EXPORT_LIMIT_NAME
        raise RateLimitExceeded("rate", "simulated exhaustion", retry_after_seconds=11)

    monkeypatch.setattr(rate_limiter, "check_request", refuse)
    with caplog.at_level("INFO", logger="ace.ai_audit"):
        response = await export_client.get("/export/alerts")

    assert response.status_code == 429
    assert response.headers["retry-after"] == "11"
    (event,) = _audit_events(caplog)
    assert event["event"] == "rate_limited"
