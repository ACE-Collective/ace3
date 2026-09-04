"""Tests for the aceapi_v2 events router.

These are real integration tests: the events endpoints read/write through the
synchronous ``get_db()`` session (via ``asyncio.to_thread``), so data is seeded
through ``get_db()`` and cleaned up by the function-scoped database reset. The
``client`` fixture authenticates as the ``unittest`` user, which is granted
wildcard (``*``/``*``) permissions in the global test setup.
"""

from datetime import date
from uuid import uuid4

import pytest
from httpx import AsyncClient

from saq.database import (
    Event,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
    get_db,
)
from saq.database.model import Alert, EventMapping, EventTagMapping, Tag, TagMapping

pytestmark = pytest.mark.integration


def _make_lookups() -> dict:
    """Create the required Event lookup rows (one OPEN + one CLOSED status)."""
    db = get_db()
    lookups = {
        "prevention_tool": EventPreventionTool(value="test_prevention_tool"),
        "remediation": EventRemediation(value="test_remediation"),
        "risk_level": EventRiskLevel(value="test_risk_level"),
        "type": EventType(value="test_type"),
        "vector": EventVector(value="test_vector"),
        "open_status": EventStatus(value="OPEN"),
        "closed_status": EventStatus(value="CLOSED"),
    }
    for obj in lookups.values():
        db.add(obj)
    db.commit()
    return lookups


def _make_event(name: str, lookups: dict, status: EventStatus) -> Event:
    db = get_db()
    event = Event(
        name=name,
        creation_date=date.today(),
        prevention_tool=lookups["prevention_tool"],
        remediation=lookups["remediation"],
        risk_level=lookups["risk_level"],
        status=status,
        type=lookups["type"],
        vector=lookups["vector"],
    )
    db.add(event)
    db.commit()
    return event


class TestOpenEvents:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get("/events/open")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_returns_only_open_events(self, client: AsyncClient):
        lookups = _make_lookups()
        _make_event("open-event", lookups, lookups["open_status"])
        _make_event("closed-event", lookups, lookups["closed_status"])

        response = await client.get("/events/open")
        assert response.status_code == 200

        data = response.json()
        assert "data" in data
        names = [e["name"] for e in data["data"]]
        assert "open-event" in names
        assert "closed-event" not in names
        # every returned event reports OPEN status
        assert all(e["status"] == "OPEN" for e in data["data"])

    @pytest.mark.asyncio
    async def test_forbidden_without_permission(self, noperm_client: AsyncClient):
        response = await noperm_client.get("/events/open")
        assert response.status_code == 403


class TestGetEvent:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get("/events/1")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_returns_event_with_alert_uuids(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("lookup-event", lookups, lookups["closed_status"])

        db = get_db()
        alert_uuids = []
        for _ in range(2):
            alert = Alert(
                uuid=str(uuid4()),
                location="test-location",
                storage_dir=f"storage/{uuid4()}",
                tool="test-tool",
                tool_instance="test-tool-instance",
                alert_type="test",
            )
            db.add(alert)
            db.flush()
            db.add(EventMapping(event_id=event.id, alert_id=alert.id))
            alert_uuids.append(alert.uuid)
        db.commit()

        response = await client.get(f"/events/{event.id}")
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == event.id
        assert data["uuid"] == event.uuid
        assert data["name"] == "lookup-event"
        # not limited to OPEN events, unlike /events/open
        assert data["status"] == "CLOSED"
        assert sorted(data["alerts"]) == sorted(alert_uuids)
        # one version token per mapped alert, matching the alerts table
        expected = {a.uuid: a.version for a in db.query(Alert).filter(Alert.uuid.in_(alert_uuids))}
        assert data["alert_versions"] == expected
        assert all(expected.values())

    @pytest.mark.asyncio
    async def test_alert_versions_follow_alert_changes(self, client: AsyncClient):
        from saq.database.util.alert import touch_alerts

        lookups = _make_lookups()
        event = _make_event("versioned-event", lookups, lookups["open_status"])

        db = get_db()
        alert = Alert(
            uuid=str(uuid4()),
            location="test-location",
            storage_dir=f"storage/{uuid4()}",
            tool="test-tool",
            tool_instance="test-tool-instance",
            alert_type="test",
        )
        db.add(alert)
        db.flush()
        db.add(EventMapping(event_id=event.id, alert_id=alert.id))
        db.commit()

        before = (await client.get(f"/events/{event.id}")).json()["alert_versions"][alert.uuid]

        touch_alerts([alert.uuid])
        db.commit()

        after = (await client.get(f"/events/{event.id}")).json()["alert_versions"][alert.uuid]
        assert after != before

    @pytest.mark.asyncio
    async def test_event_without_alerts_has_empty_list(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("empty-event", lookups, lookups["open_status"])

        response = await client.get(f"/events/{event.id}")
        assert response.status_code == 200
        assert response.json()["alerts"] == []
        assert response.json()["alert_versions"] == {}

    @pytest.mark.asyncio
    async def test_unknown_event_returns_404(self, client: AsyncClient):
        _make_lookups()
        response = await client.get("/events/999999")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_forbidden_without_permission(self, noperm_client: AsyncClient):
        response = await noperm_client.get("/events/1")
        assert response.status_code == 403


class TestUpdateEventStatus:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.patch("/events/1", json={"status": "CLOSED"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_updates_status(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("status-event", lookups, lookups["open_status"])

        response = await client.patch(
            f"/events/{event.id}", json={"status": "CLOSED"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "CLOSED"

    @pytest.mark.asyncio
    async def test_unknown_event_returns_404(self, client: AsyncClient):
        _make_lookups()
        response = await client.patch("/events/999999", json={"status": "CLOSED"})
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_status_returns_400(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("bad-status-event", lookups, lookups["open_status"])

        response = await client.patch(
            f"/events/{event.id}", json={"status": "NOT_A_REAL_STATUS"}
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_forbidden_without_permission(self, noperm_client: AsyncClient):
        response = await noperm_client.patch("/events/1", json={"status": "CLOSED"})
        assert response.status_code == 403


class TestExportEvents:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get("/events/export", params={"type": "csv"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_exports_csv(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("export-event", lookups, lookups["open_status"])

        response = await client.get(
            "/events/export",
            params={"type": "csv", "checked_events[]": [event.id]},
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")

        body = response.text
        # header row + the seeded event's data row
        assert '"id","uuid","creation_date"' in body
        assert '"export-event"' in body

    @pytest.mark.asyncio
    async def test_exports_csv_separates_event_and_alert_tags(self, client: AsyncClient):
        """Event CSV export has distinct ``tags`` (direct) and ``alert_tags`` (inherited) columns."""
        lookups = _make_lookups()
        event = _make_event("tagged-event", lookups, lookups["open_status"])

        db = get_db()
        alert = Alert(
            uuid=str(uuid4()),
            location="test-location",
            storage_dir=f"storage/{uuid4()}",
            tool="test-tool",
            tool_instance="test-tool-instance",
            alert_type="test",
        )
        db.add(alert)
        db.flush()

        event_tag = Tag(name="mitre:TA0011")
        alert_tag = Tag(name="mitre:T1105")
        db.add_all([event_tag, alert_tag])
        db.flush()

        db.add(EventTagMapping(event_id=event.id, tag_id=event_tag.id))
        db.add(TagMapping(alert_id=alert.id, tag_id=alert_tag.id))
        db.add(EventMapping(event_id=event.id, alert_id=alert.id))
        db.commit()

        response = await client.get(
            "/events/export",
            params={"type": "csv", "checked_events[]": [event.id]},
        )
        assert response.status_code == 200

        body = response.text
        lines = body.splitlines()
        header = lines[0]
        assert '"tags"' in header
        assert '"alert_tags"' in header

        # the row for our event must contain both tag names, each in its own column
        event_row = next(line for line in lines[1:] if '"tagged-event"' in line)
        tags_idx = header.split(",").index('"tags"')
        alert_tags_idx = header.split(",").index('"alert_tags"')
        cells = event_row.split(",")
        assert "mitre:TA0011" in cells[tags_idx]
        assert "mitre:T1105" not in cells[tags_idx]
        assert "mitre:T1105" in cells[alert_tags_idx]
        assert "mitre:TA0011" not in cells[alert_tags_idx]

    @pytest.mark.asyncio
    async def test_unsupported_format_returns_422(self, client: AsyncClient):
        response = await client.get("/events/export", params={"type": "xml"})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_forbidden_without_permission(self, noperm_client: AsyncClient):
        response = await noperm_client.get("/events/export", params={"type": "csv"})
        assert response.status_code == 403


class TestGetEventByReferenceAndAlertDetails:
    """GET /events/{ref} takes a numeric id or the event's uuid, and carries each mapped alert's
    database state under alert_details -- the columns the alert's storage directory never holds."""

    @pytest.mark.asyncio
    async def test_lookup_by_uuid_matches_lookup_by_id(self, client: AsyncClient):
        lookups = _make_lookups()
        event = _make_event("by-uuid", lookups, lookups["open_status"])
        by_id = (await client.get(f"/events/{event.id}")).json()
        response = await client.get(f"/events/{event.uuid}")
        assert response.status_code == 200
        assert response.json() == by_id
        assert by_id["uuid"] == event.uuid

    @pytest.mark.asyncio
    async def test_malformed_reference_is_400_and_unknown_uuid_is_404(self, client: AsyncClient):
        assert (await client.get("/events/not-an-id")).status_code == 400
        assert (await client.get("/events/11111111-1111-1111-1111-111111111111")).status_code == 404

    @pytest.mark.asyncio
    async def test_alert_details_carry_database_state(self, client: AsyncClient):
        from datetime import datetime, timezone

        from saq.database import EventMapping, User, get_db
        from tests.saq.helpers import insert_alert

        lookups = _make_lookups()
        event = _make_event("with-details", lookups, lookups["open_status"])
        alert = insert_alert()
        db = get_db()
        analyst = db.query(User).filter(User.username == "unittest").one()
        when = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
        alert.owner_id = analyst.id
        alert.owner_time = when
        alert.disposition = "FALSE_POSITIVE"
        alert.disposition_user_id = analyst.id
        alert.disposition_time = when
        db.add(EventMapping(event_id=event.id, alert_id=alert.id))
        db.commit()

        body = (await client.get(f"/events/{event.id}")).json()
        assert [d["uuid"] for d in body["alert_details"]] == [alert.uuid]
        detail = body["alert_details"][0]
        assert detail["owner"] == "unittest"
        assert detail["disposition"] == "FALSE_POSITIVE"
        assert detail["disposition_user"] == "unittest"
        assert detail["owner_time"].startswith("2026-09-02T12:00:00")
        assert detail["disposition_time"].startswith("2026-09-02T12:00:00")
        assert detail["insert_date"]  # set by the database on insert

    @pytest.mark.asyncio
    async def test_event_with_malware_serializes_threat_names(self, client: AsyncClient):
        """Event.json read `t.type` on a Threat row, which only has `threat_type`: every event with malware
        tagged answered 500 on both APIs."""
        from saq.database import Malware, MalwareMapping, Threat, ThreatType, get_db

        lookups = _make_lookups()
        event = _make_event("with-malware", lookups, lookups["open_status"])
        db = get_db()
        ttype = ThreatType(name="ai-test-rat")
        malware = Malware(name="ai-test-family")
        db.add_all([ttype, malware])
        db.commit()
        db.add(Threat(malware_id=malware.id, threat_type_id=ttype.id))
        db.add(MalwareMapping(event_id=event.id, malware_id=malware.id))
        db.commit()

        response = await client.get(f"/events/{event.id}")
        assert response.status_code == 200
        assert response.json()["malware"] == [{"ai-test-family": ["ai-test-rat"]}]

    @pytest.mark.asyncio
    async def test_disposition_time_is_the_disposition_time(self, client: AsyncClient):
        """Event.json used to emit ownership_time under the disposition_time key."""
        from datetime import datetime

        from saq.database import get_db

        lookups = _make_lookups()
        event = _make_event("times", lookups, lookups["open_status"])
        event.ownership_time = datetime(2026, 9, 1, 8, 0, 0)
        event.disposition_time = datetime(2026, 9, 3, 9, 30, 0)
        get_db().commit()
        body = (await client.get(f"/events/{event.id}")).json()
        assert body["ownership_time"] == "2026-09-01 08:00:00"
        assert body["disposition_time"] == "2026-09-03 09:30:00"
