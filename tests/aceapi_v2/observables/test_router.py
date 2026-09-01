"""Tests for aceapi_v2 observables router."""

import hashlib
from datetime import date, datetime
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import (
    Alert,
    Event,
    EventMapping,
    EventPreventionTool,
    EventRemediation,
    EventRiskLevel,
    EventStatus,
    EventType,
    EventVector,
    Observable,
    ObservableMapping,
)

pytestmark = pytest.mark.integration


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf8", errors="ignore")).digest()


def _alert(disposition: str = "OPEN", alert_type: str = "test",
           insert_date: datetime | None = None) -> Alert:
    return Alert(
        uuid=str(uuid4()),
        location="test-location",
        storage_dir=f"test/{uuid4()}",
        tool="test-tool",
        tool_instance="test-tool-instance",
        alert_type=alert_type,
        disposition=disposition,
        insert_date=insert_date or datetime(2026, 1, 1, 12, 0, 0),
    )


def _observable(otype: str, value: str) -> Observable:
    return Observable(type=otype, sha256=_sha256(value), value=value.encode("utf8"))


async def _seed_mapped_alerts(session: AsyncSession, observable: Observable,
                              alerts: list[Alert]) -> None:
    session.add(observable)
    for alert in alerts:
        session.add(alert)
    await session.flush()
    for alert in alerts:
        session.add(ObservableMapping(observable_id=observable.id, alert_id=alert.id))
    await session.commit()


async def _event_lookups(session: AsyncSession) -> dict:
    lookups = {
        "prevention_tool": EventPreventionTool(value="test_prevention_tool"),
        "remediation": EventRemediation(value="test_remediation"),
        "risk_level": EventRiskLevel(value="test_risk_level"),
        "type": EventType(value="test_type"),
        "vector": EventVector(value="test_vector"),
        "open_status": EventStatus(value="OPEN"),
    }
    for obj in lookups.values():
        session.add(obj)
    await session.flush()
    return lookups


async def _event(session: AsyncSession, name: str, lookups: dict,
                 alerts: list[Alert]) -> Event:
    event = Event(
        name=name,
        creation_date=date(2026, 1, 15),
        prevention_tool=lookups["prevention_tool"],
        remediation=lookups["remediation"],
        risk_level=lookups["risk_level"],
        status=lookups["open_status"],
        type=lookups["type"],
        vector=lookups["vector"],
    )
    session.add(event)
    await session.flush()
    for alert in alerts:
        session.add(EventMapping(event_id=event.id, alert_id=alert.id))
    await session.commit()
    return event


def _lookup_body(*pairs: tuple[str, str], **kwargs) -> dict:
    body = {"observables": [{"type": t, "value": v} for t, v in pairs]}
    body.update(kwargs)
    return body


class TestSetInteresting:
    """Test the PATCH /observables/interesting endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "192.168.1.1",
                "is_interesting": True,
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_mark_existing_observable_interesting(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Mark an existing observable as interesting."""
        obs = Observable(
            type="ipv4", sha256=_sha256("192.168.1.1"), value=b"192.168.1.1"
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "192.168.1.1",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        # Expire cached state so we re-read from DB
        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "ipv4",
                Observable.sha256 == _sha256("192.168.1.1"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True

    @pytest.mark.asyncio
    async def test_mark_nonexistent_observable_creates_it(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Marking a nonexistent observable as interesting should create it."""
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "domain",
                "observable_value": "evil.com",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        result = await session.execute(
            select(Observable).where(
                Observable.type == "domain",
                Observable.sha256 == _sha256("evil.com"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True
        assert db_obs.value == b"evil.com"

    @pytest.mark.asyncio
    async def test_unmark_observable_interesting(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Unmark an observable that was previously interesting."""
        obs = Observable(
            type="url",
            sha256=_sha256("https://evil.com"),
            value=b"https://evil.com",
            is_interesting=True,
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "url",
                "observable_value": "https://evil.com",
                "is_interesting": False,
            },
        )
        assert response.status_code == 200

        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "url",
                Observable.sha256 == _sha256("https://evil.com"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is False

    @pytest.mark.asyncio
    async def test_unmark_nonexistent_observable_is_noop(
        self, client: AsyncClient
    ):
        """Unmarking a nonexistent observable should succeed without creating it."""
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "10.0.0.1",
                "is_interesting": False,
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_toggle_interesting_idempotent(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Marking as interesting twice should be idempotent."""
        obs = Observable(
            type="ipv4",
            sha256=_sha256("1.2.3.4"),
            value=b"1.2.3.4",
            is_interesting=True,
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "1.2.3.4",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "ipv4",
                Observable.sha256 == _sha256("1.2.3.4"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True

    @pytest.mark.asyncio
    async def test_does_not_affect_other_fields(
        self, session: AsyncSession, client: AsyncClient
    ):
        """Marking as interesting should not change other fields like for_detection."""
        obs = Observable(
            type="domain",
            sha256=_sha256("test.com"),
            value=b"test.com",
            for_detection=True,
        )
        session.add(obs)
        await session.commit()

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "domain",
                "observable_value": "test.com",
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        session.expire_all()
        result = await session.execute(
            select(Observable).where(
                Observable.type == "domain",
                Observable.sha256 == _sha256("test.com"),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True
        assert db_obs.for_detection is True

    @pytest.mark.asyncio
    async def test_response_message(self, client: AsyncClient):
        """Verify response message content."""
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "8.8.8.8",
                "is_interesting": True,
            },
        )
        assert response.json()["message"] == "Observable marked as interesting"

        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "ipv4",
                "observable_value": "8.8.8.8",
                "is_interesting": False,
            },
        )
        assert response.json()["message"] == "Observable unmarked as interesting"

    @pytest.mark.asyncio
    async def test_file_observable_uses_content_hash_identity(
        self, session: AsyncSession, client: AsyncClient
    ):
        """A file observable's DB identity is unhex(value), not sha256(value)."""
        content_hash = "ab" * 32
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "file",
                "observable_value": content_hash.upper(),
                "is_interesting": True,
            },
        )
        assert response.status_code == 200

        result = await session.execute(
            select(Observable).where(
                Observable.type == "file",
                Observable.sha256 == bytes.fromhex(content_hash),
            )
        )
        db_obs = result.scalar_one()
        assert db_obs.is_interesting is True
        assert db_obs.value == content_hash.encode("utf8")

    @pytest.mark.asyncio
    async def test_invalid_value_returns_400(self, client: AsyncClient):
        response = await client.patch(
            "/observables/interesting",
            json={
                "observable_type": "file",
                "observable_value": "not-a-hex-digest",
                "is_interesting": True,
            },
        )
        assert response.status_code == 400


class TestObservableLookup:
    """Test the POST /observables/lookup endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.post(
            "/observables/lookup", json=_lookup_body(("ipv4", "1.2.3.4")))
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_requires_permission(self, noperm_client: AsyncClient):
        response = await noperm_client.post(
            "/observables/lookup", json=_lookup_body(("ipv4", "1.2.3.4")))
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_request_bounds_are_422(self, client: AsyncClient):
        response = await client.post("/observables/lookup", json={"observables": []})
        assert response.status_code == 422

        too_many = [{"type": "ipv4", "value": f"10.0.{i // 256}.{i % 256}"} for i in range(1001)]
        response = await client.post("/observables/lookup", json={"observables": too_many})
        assert response.status_code == 422

        for bad_limit in (21, -1):
            response = await client.post(
                "/observables/lookup",
                json=_lookup_body(("ipv4", "1.2.3.4"), recent_alert_limit=bad_limit))
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_unknown_observable(self, client: AsyncClient):
        response = await client.post(
            "/observables/lookup", json=_lookup_body(("ipv4", "203.0.113.99")))
        assert response.status_code == 200
        (result,) = response.json()["results"]
        assert result["index"] == 0
        assert result["found"] is False
        assert result["error"] is None
        assert result["total_alert_count"] == 0
        assert result["disposition_counts"] == {}
        assert result["recent_alerts"] == []
        assert result["events"] == []

    @pytest.mark.asyncio
    async def test_per_pair_errors_do_not_fail_the_batch(
        self, session: AsyncSession, client: AsyncClient
    ):
        await _seed_mapped_alerts(session, _observable("ipv4", "198.51.100.7"), [_alert()])

        response = await client.post("/observables/lookup", json=_lookup_body(
            ("ipv4", "not-an-ip"),
            ("file", "not-a-hex-digest"),
            ("ipv4", "198.51.100.7"),
        ))
        assert response.status_code == 200
        results = response.json()["results"]
        assert [r["index"] for r in results] == [0, 1, 2]
        assert results[0]["error"] and results[0]["found"] is False
        assert results[1]["error"] and results[1]["found"] is False
        assert results[2]["error"] is None
        assert results[2]["found"] is True
        assert results[2]["total_alert_count"] == 1

    @pytest.mark.asyncio
    async def test_file_identity_and_normalized_echo(
        self, session: AsyncSession, client: AsyncClient
    ):
        """File observables match on unhex(value), and the echoed value is the normalized
        (lowercased) form."""
        content_hash = "cd" * 32
        observable = Observable(
            type="file", sha256=bytes.fromhex(content_hash), value=content_hash.encode("utf8"))
        await _seed_mapped_alerts(session, observable, [_alert(disposition="DELIVERY")])

        response = await client.post(
            "/observables/lookup", json=_lookup_body(("file", content_hash.upper())))
        (result,) = response.json()["results"]
        assert result["found"] is True
        assert result["value"] == content_hash
        assert result["total_alert_count"] == 1
        assert result["disposition_counts"] == {"DELIVERY": 1}

    @pytest.mark.asyncio
    async def test_histogram_totals_and_seen_range(
        self, session: AsyncSession, client: AsyncClient
    ):
        alerts = [
            _alert("FALSE_POSITIVE", insert_date=datetime(2025, 3, 1)),
            _alert("FALSE_POSITIVE", insert_date=datetime(2025, 6, 1)),
            _alert("DELIVERY", insert_date=datetime(2025, 9, 1)),
            _alert("OPEN", insert_date=datetime(2026, 1, 1)),
            _alert("UNKNOWN", insert_date=datetime(2026, 2, 1)),
            _alert("FALSE_POSITIVE", alert_type="faqueue", insert_date=datetime(2026, 3, 1)),
        ]
        await _seed_mapped_alerts(session, _observable("ipv4", "203.0.113.7"), alerts)

        response = await client.post(
            "/observables/lookup", json=_lookup_body(("ipv4", "203.0.113.7")))
        (result,) = response.json()["results"]
        assert result["found"] is True
        assert result["disposition_counts"] == {
            "FALSE_POSITIVE": 2, "DELIVERY": 1, "OPEN": 1, "UNKNOWN": 1}
        assert result["total_alert_count"] == 5  # faqueue alert not counted
        assert result["first_seen"].startswith("2025-03-01")
        assert result["last_seen"].startswith("2026-02-01")
        # the faqueue alert is also absent from recent alerts
        recent_uuids = {a["uuid"] for a in result["recent_alerts"]}
        assert alerts[5].uuid not in recent_uuids

    @pytest.mark.asyncio
    async def test_exclude_alert_uuids(self, session: AsyncSession, client: AsyncClient):
        excluded = _alert("FALSE_POSITIVE", insert_date=datetime(2026, 2, 1))
        kept = _alert("DELIVERY", insert_date=datetime(2026, 1, 1))
        await _seed_mapped_alerts(session, _observable("ipv4", "203.0.113.8"), [excluded, kept])

        response = await client.post("/observables/lookup", json=_lookup_body(
            ("ipv4", "203.0.113.8"),
            exclude_alert_uuids=[excluded.uuid, str(uuid4())],  # unknown uuid is ignored
        ))
        (result,) = response.json()["results"]
        assert result["total_alert_count"] == 1
        assert result["disposition_counts"] == {"DELIVERY": 1}
        assert [a["uuid"] for a in result["recent_alerts"]] == [kept.uuid]

    @pytest.mark.asyncio
    async def test_recent_alerts_newest_first_and_limited(
        self, session: AsyncSession, client: AsyncClient
    ):
        alerts = [_alert(insert_date=datetime(2026, 1, day)) for day in (1, 3, 2, 4)]
        await _seed_mapped_alerts(session, _observable("ipv4", "203.0.113.9"), alerts)

        response = await client.post("/observables/lookup", json=_lookup_body(
            ("ipv4", "203.0.113.9"), recent_alert_limit=2))
        (result,) = response.json()["results"]
        assert result["total_alert_count"] == 4
        assert [a["uuid"] for a in result["recent_alerts"]] == [alerts[3].uuid, alerts[1].uuid]

    @pytest.mark.asyncio
    async def test_recent_alert_limit_zero_returns_counts_only(
        self, session: AsyncSession, client: AsyncClient
    ):
        await _seed_mapped_alerts(session, _observable("ipv4", "203.0.113.10"), [_alert()])

        response = await client.post("/observables/lookup", json=_lookup_body(
            ("ipv4", "203.0.113.10"), recent_alert_limit=0))
        (result,) = response.json()["results"]
        assert result["total_alert_count"] == 1
        assert result["recent_alerts"] == []

    @pytest.mark.asyncio
    async def test_event_membership(self, session: AsyncSession, client: AsyncClient):
        in_event_a1 = _alert(insert_date=datetime(2025, 1, 1))
        in_event_a2 = _alert(insert_date=datetime(2025, 1, 2))
        in_event_b = _alert(insert_date=datetime(2025, 1, 3))
        no_event = _alert(insert_date=datetime(2025, 1, 4))
        observable = _observable("ipv4", "203.0.113.11")
        await _seed_mapped_alerts(session, observable, [in_event_a1, in_event_a2, in_event_b, no_event])

        other = _observable("ipv4", "203.0.113.12")
        other_alert = _alert()
        await _seed_mapped_alerts(session, other, [other_alert])

        lookups = await _event_lookups(session)
        event_a = await _event(session, "event-a", lookups, [in_event_a1, in_event_a2])
        event_b = await _event(session, "event-b", lookups, [in_event_b])
        # an event holding only an unrelated alert must not appear
        await _event(session, "event-c", lookups, [other_alert])

        response = await client.post("/observables/lookup", json=_lookup_body(
            ("ipv4", "203.0.113.11"),
            # since after every alert: counts drop but event memberships remain
            since="2027-01-01T00:00:00",
        ))
        (result,) = response.json()["results"]
        assert result["total_alert_count"] == 0
        events = {e["name"]: e for e in result["events"]}
        assert set(events) == {"event-a", "event-b"}  # event-a de-duplicated across two alerts
        assert events["event-a"]["id"] == event_a.id
        assert events["event-a"]["uuid"] == event_a.uuid
        assert events["event-a"]["creation_date"] == "2026-01-15"
        assert events["event-a"]["status"] == "OPEN"
        assert events["event-b"]["id"] == event_b.id

    @pytest.mark.asyncio
    async def test_since_bounds_counts(self, session: AsyncSession, client: AsyncClient):
        older = _alert("FALSE_POSITIVE", insert_date=datetime(2025, 1, 1))
        newer = _alert("DELIVERY", insert_date=datetime(2026, 1, 1))
        await _seed_mapped_alerts(session, _observable("ipv4", "203.0.113.13"), [older, newer])

        response = await client.post("/observables/lookup", json=_lookup_body(
            ("ipv4", "203.0.113.13"), since="2025-06-01T00:00:00"))
        (result,) = response.json()["results"]
        assert result["total_alert_count"] == 1
        assert result["disposition_counts"] == {"DELIVERY": 1}
        assert result["first_seen"].startswith("2026-01-01")
        assert [a["uuid"] for a in result["recent_alerts"]] == [newer.uuid]

    @pytest.mark.asyncio
    async def test_duplicate_pairs_each_get_a_result(
        self, session: AsyncSession, client: AsyncClient
    ):
        await _seed_mapped_alerts(session, _observable("ipv4", "203.0.113.14"), [_alert()])

        response = await client.post("/observables/lookup", json=_lookup_body(
            ("ipv4", "203.0.113.14"), ("ipv4", "192.0.2.55"), ("ipv4", "203.0.113.14")))
        results = response.json()["results"]
        assert [r["index"] for r in results] == [0, 1, 2]
        assert results[0]["found"] and results[2]["found"]
        assert results[0]["total_alert_count"] == results[2]["total_alert_count"] == 1
        assert results[1]["found"] is False
