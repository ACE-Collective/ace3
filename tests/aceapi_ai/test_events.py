"""The AI app's event route: ai:event gating over the shared v2 event service."""

from datetime import date

import pytest

pytestmark = pytest.mark.integration


def _make_event(name: str):
    from saq.database import (Event, EventPreventionTool, EventRemediation, EventRiskLevel, EventStatus, EventType,
                              EventVector, get_db)

    db = get_db()
    lookups = {
        "prevention_tool": EventPreventionTool(value="ai-test-tool"),
        "remediation": EventRemediation(value="ai-test-remediation"),
        "risk_level": EventRiskLevel(value="ai-test-risk"),
        "type": EventType(value="ai-test-type"),
        "vector": EventVector(value="ai-test-vector"),
        "status": EventStatus(value="OPEN"),
    }
    for obj in lookups.values():
        db.add(obj)
    db.commit()
    event = Event(name=name, creation_date=date.today(), prevention_tool=lookups["prevention_tool"],
                  remediation=lookups["remediation"], risk_level=lookups["risk_level"], status=lookups["status"],
                  type=lookups["type"], vector=lookups["vector"])
    db.add(event)
    db.commit()
    return event


@pytest.mark.asyncio
async def test_event_requires_auth(unauth_client):
    assert (await unauth_client.get("/events/1")).status_code == 401


@pytest.mark.asyncio
async def test_event_requires_ai_event_scope(_override_db_session, session, test_user):
    from tests.aceapi_ai.conftest import api_key_client
    from tests.aceapi_v2.conftest import make_api_key

    key = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "fake"), ("ai", "alert")])
    async with api_key_client(key) as client:
        assert (await client.get("/events/1")).status_code == 403


@pytest.mark.asyncio
async def test_event_missing_is_404_and_malformed_is_400(ai_scoped_client):
    assert (await ai_scoped_client.get("/events/999999")).status_code == 404
    assert (await ai_scoped_client.get("/events/11111111-1111-1111-1111-111111111111")).status_code == 404
    assert (await ai_scoped_client.get("/events/not-a-ref")).status_code == 400


@pytest.mark.asyncio
async def test_event_by_id_or_uuid_returns_metadata_versions_and_details(ai_scoped_client):
    from saq.database import EventMapping, get_db
    from tests.saq.helpers import insert_alert

    event = _make_event("ai-event")
    alert = insert_alert()
    db = get_db()
    db.add(EventMapping(event_id=event.id, alert_id=alert.id))
    db.commit()

    response = await ai_scoped_client.get(f"/events/{event.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == event.id
    assert body["name"] == "ai-event"
    assert body["alerts"] == [alert.uuid]
    assert set(body["alert_versions"]) == {alert.uuid}
    detail = body["alert_details"][0]
    assert detail["uuid"] == alert.uuid
    assert detail["insert_date"]
    assert detail["owner"] is None and detail["owner_time"] is None   # fresh alert: unowned
    assert detail["disposition"] == "OPEN" and detail["disposition_user"] is None

    assert (await ai_scoped_client.get(f"/events/{event.uuid}")).json() == body
