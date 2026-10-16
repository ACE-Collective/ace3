"""/api/v2/remediation: the alert pages' remediation dialog and the Remediations page."""

import csv
import io
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.configuration.schema import ConfigApiKey
from saq.constants import F_TEST
from saq.database.model import Remediation, RemediationHistory, User
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.database.util.user_management import add_user
from saq.remediation.target import ObservableRemediationInterface, RemediationTarget, register_observable_remediation_interface
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus
from saq.util import sha256_str
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

# the unittest configuration's remediator (remediator_test in etc/saq.unittest.default.yaml)
REMEDIATOR = "test"


class _TestTargets(ObservableRemediationInterface):
    def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
        return [RemediationTarget(REMEDIATOR, observable.type, observable.value)]


@pytest.fixture
def remediable():
    """test observables have one remediation target each, with the configured test remediator."""
    register_observable_remediation_interface(F_TEST, _TestTargets())


def _alert_with(*values: str) -> str:
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    for value in values:
        root.add_observable_by_spec(F_TEST, value)
    root.save()
    ALERT(root)
    return root.uuid


def _target(value: str) -> dict:
    return {"remediator": REMEDIATOR, "observable_type": F_TEST, "observable_value": value}


def _caller_id() -> int:
    return get_db().query(User).filter(User.username == "unittest").one().id


def _queue(value: str, status: RemediationStatus = RemediationStatus.NEW, result: RemediatorStatus | None = None,
           action: RemediationAction = RemediationAction.REMOVE, restore_key: str | None = None) -> int:
    target = RemediationTarget(REMEDIATOR, F_TEST, value)
    remediation_id = target.queue_remediation(action, _caller_id(), restore_key)
    db = get_db()
    db.execute(Remediation.__table__.update().where(Remediation.id == remediation_id).values(
        status=status.value, result=result.value if result else None))
    db.commit()
    return remediation_id


def _remediation(remediation_id: int) -> Remediation | None:
    db = get_db()
    db.expire_all()
    return db.get(Remediation, remediation_id)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _set(remediation_id: int, **values) -> None:
    db = get_db()
    db.execute(Remediation.__table__.update().where(Remediation.id == remediation_id).values(**values))
    db.commit()


def _history(remediation_id: int, message: str, when: datetime, result: RemediatorStatus = RemediatorStatus.DELAYED) -> None:
    db = get_db()
    db.add(RemediationHistory(remediation_id=remediation_id, result=result.value,
                              status=RemediationStatus.IN_PROGRESS.value, message=message, insert_date=when))
    db.commit()


async def _ids(client: AsyncClient, *f: str) -> list[int]:
    response = await client.get("/remediation/remediations", params={"f": list(f)})
    assert response.status_code == 200, response.text
    return [row["id"] for row in response.json()["data"]]


class TestAccess:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.post("/remediation/targets/lookup", json={"alert_uuids": ["x"]})).status_code == 401
        assert (await unauth_client.post("/remediation/remediations/1/cancel")).status_code == 401

    @pytest.mark.asyncio
    async def test_lookup_requires_remediation_read(self, noperm_client: AsyncClient):
        assert (await noperm_client.post("/remediation/targets/lookup", json={"alert_uuids": ["x"]})).status_code == 403

    @pytest.mark.asyncio
    async def test_writes_require_remediation_write(self, _override_db_session, session: AsyncSession, test_user, remediable):
        """remediation:read lists targets but cannot remediate them."""
        alert_uuid = _alert_with("evil")
        remediation_id = _queue("other")
        key = await make_api_key(session, test_user.id, inherit=False, scope=[("remediation", "read")])

        async with api_key_client(key) as reader:
            assert (await reader.post("/remediation/targets/lookup", json={"alert_uuids": [alert_uuid]})).status_code == 200
            response = await reader.post("/remediation/remediations", json={"action": "remove", "targets": [_target("evil")]})
            assert response.status_code == 403
            assert (await reader.post(f"/remediation/remediations/{remediation_id}/cancel")).status_code == 403
            assert (await reader.post(f"/remediation/remediations/{remediation_id}/retry")).status_code == 403
            assert (await reader.post(f"/remediation/remediations/{remediation_id}/restore")).status_code == 403
            assert (await reader.delete(f"/remediation/remediations/{remediation_id}")).status_code == 403
            # reading the Remediations page's list and history is remediation:read
            assert (await reader.get("/remediation/remediations")).status_code == 200
            assert (await reader.get(f"/remediation/remediations/{remediation_id}/history")).status_code == 200

        assert get_db().query(Remediation).count() == 1

    @pytest.mark.asyncio
    async def test_the_list_requires_remediation_read(self, noperm_client: AsyncClient):
        assert (await noperm_client.get("/remediation/remediations")).status_code == 403
        assert (await noperm_client.get("/remediation/remediations/export/csv")).status_code == 403
        assert (await noperm_client.get("/remediation/remediations/1/history")).status_code == 403

    @pytest.mark.asyncio
    async def test_a_key_that_is_not_a_user_cannot_remediate(self, _override_db_session, monkeypatch, remediable):
        plaintext = "6a0c3b5e-0f1d-4b8e-9a7c-2e4f6d8b0a1c"
        monkeypatch.setattr(get_config(), "apikeys", {
            "service": ConfigApiKey(key=sha256_str(plaintext), scope=["remediation:write"]),
        })

        async with api_key_client(plaintext) as service_client:
            response = await service_client.post("/remediation/remediations", json={"action": "remove", "targets": [_target("evil")]})

        assert response.status_code == 400


class TestLookup:
    @pytest.mark.asyncio
    async def test_targets_of_the_alerts_with_their_latest_remediation(self, client: AsyncClient, remediable):
        first = _alert_with("evil", "worse")
        second = _alert_with("evil")
        _queue("worse", RemediationStatus.COMPLETED, RemediatorStatus.FAILED)
        latest = _queue("worse")

        response = await client.post("/remediation/targets/lookup", json={"alert_uuids": [first, second]})

        assert response.status_code == 200
        targets = response.json()["data"]
        # one row per target, however many alerts share it
        assert [target["observable_value"] for target in targets] == ["evil", "worse"]
        evil, worse = targets
        assert evil == {**_target("evil"), "remediator_display_name": "Test Remediator", "current": None}
        assert worse["current"] == {"id": latest, "action": "remove", "status": "NEW", "result": None}

    @pytest.mark.asyncio
    async def test_needs_at_least_one_alert(self, client: AsyncClient):
        assert (await client.post("/remediation/targets/lookup", json={"alert_uuids": []})).status_code == 422

    @pytest.mark.asyncio
    async def test_targets_of_observables(self, client: AsyncClient, remediable):
        """Add Remediation on the Remediations page: the targets of typed-in values."""
        latest = _queue("worse")

        response = await client.post("/remediation/targets/lookup", json={"observables": [
            {"type": F_TEST, "value": "worse"}, {"type": F_TEST, "value": "evil"}, {"type": F_TEST, "value": "evil"}]})

        assert response.status_code == 200
        evil, worse = response.json()["data"]
        assert evil == {**_target("evil"), "remediator_display_name": "Test Remediator", "current": None}
        assert worse["current"]["id"] == latest

    @pytest.mark.asyncio
    async def test_a_value_its_type_rejects_is_named(self, client: AsyncClient, remediable):
        response = await client.post("/remediation/targets/lookup", json={"observables": [
            {"type": F_TEST, "value": "evil"}, {"type": "ipv4", "value": "not an ip"}]})

        assert response.status_code == 422
        assert "ipv4 'not an ip'" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_type_no_remediator_handles_has_no_targets(self, client: AsyncClient):
        response = await client.post("/remediation/targets/lookup", json={"observables": [{"type": "ipv4", "value": "1.2.3.4"}]})

        assert response.status_code == 200
        assert response.json()["data"] == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("body", [
        {},
        {"alert_uuids": [str(uuid.uuid4())], "observables": [{"type": F_TEST, "value": "evil"}]},
    ])
    async def test_alerts_or_observables(self, client: AsyncClient, body):
        assert (await client.post("/remediation/targets/lookup", json=body)).status_code == 422


class TestQueue:
    @pytest.mark.asyncio
    async def test_remove(self, client: AsyncClient, remediable, caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO, logger="aceapi_v2.remediation.router")

        response = await client.post("/remediation/remediations",
                                     json={"action": "remove", "targets": [_target("evil"), _target("worse")]})

        assert response.status_code == 201
        queued = response.json()["data"]
        assert [(r["action"], r["status"]) for r in queued] == [("remove", "NEW"), ("remove", "NEW")]
        rows = [_remediation(r["id"]) for r in queued]
        assert [(row.key, row.user_id) for row in rows] == [("evil", _caller_id()), ("worse", _caller_id())]
        assert any(record.getMessage().startswith("AUDIT: user unittest queued remove remediations")
                   for record in caplog.records)

    @pytest.mark.asyncio
    async def test_restore_uses_the_latest_successful_removal(self, client: AsyncClient, remediable):
        _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS, restore_key="old-key")
        _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS, restore_key="the-key")
        _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.FAILED, restore_key="failed-key")

        response = await client.post("/remediation/remediations", json={"action": "restore", "targets": [_target("evil")]})

        (queued,) = response.json()["data"]
        assert queued["action"] == "restore"
        assert _remediation(queued["id"]).restore_key == "the-key"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("target", [
        {"remediator": "no_such_remediator", "observable_type": F_TEST, "observable_value": "evil"},
        {"remediator": REMEDIATOR, "observable_type": "ipv4", "observable_value": "not an ip"},
    ])
    async def test_a_bad_target_queues_nothing(self, client: AsyncClient, remediable, target):
        response = await client.post("/remediation/remediations", json={"action": "remove", "targets": [_target("evil"), target]})

        assert response.status_code == 422
        assert get_db().query(Remediation).count() == 0

    @pytest.mark.asyncio
    async def test_unknown_action_is_422(self, client: AsyncClient):
        response = await client.post("/remediation/remediations", json={"action": "obliterate", "targets": [_target("evil")]})
        assert response.status_code == 422


class TestCancel:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [RemediationStatus.NEW, RemediationStatus.IN_PROGRESS])
    async def test_stops_a_remediation_that_has_not_completed(self, client: AsyncClient, status):
        remediation_id = _queue("evil", status)

        response = await client.post(f"/remediation/remediations/{remediation_id}/cancel")

        assert response.status_code == 200
        assert response.json() == {"id": remediation_id, "action": "remove", "status": "COMPLETED", "result": "CANCELLED"}
        history = get_db().query(RemediationHistory).filter(RemediationHistory.remediation_id == remediation_id).one()
        assert history.message == "cancelled by unittest"

    @pytest.mark.asyncio
    async def test_a_completed_remediation_keeps_its_result(self, client: AsyncClient):
        """The dialog's Stop used to overwrite a finished remediation's result with CANCELLED."""
        remediation_id = _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS)

        response = await client.post(f"/remediation/remediations/{remediation_id}/cancel")

        assert response.status_code == 409
        assert _remediation(remediation_id).result == RemediatorStatus.SUCCESS.value
        assert get_db().query(RemediationHistory).filter(RemediationHistory.remediation_id == remediation_id).count() == 0

    @pytest.mark.asyncio
    async def test_unknown_remediation(self, client: AsyncClient):
        assert (await client.post("/remediation/remediations/999999/cancel")).status_code == 404


class TestDelete:
    @pytest.mark.asyncio
    async def test_delete(self, client: AsyncClient):
        remediation_id = _queue("evil")

        assert (await client.delete(f"/remediation/remediations/{remediation_id}")).status_code == 204
        assert _remediation(remediation_id) is None

    @pytest.mark.asyncio
    async def test_unknown_remediation(self, client: AsyncClient):
        assert (await client.delete("/remediation/remediations/999999")).status_code == 404


class TestRetry:
    @pytest.mark.asyncio
    async def test_queues_a_completed_remediation_again(self, client: AsyncClient, caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO, logger="aceapi_v2.remediation.router")
        remediation_id = _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.FAILED)

        response = await client.post(f"/remediation/remediations/{remediation_id}/retry")

        assert response.status_code == 200
        assert response.json() == {"id": remediation_id, "action": "remove", "status": "NEW", "result": None}
        assert any(record.getMessage() == f"AUDIT: user unittest retried remediation {remediation_id}"
                   for record in caplog.records)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [RemediationStatus.NEW, RemediationStatus.IN_PROGRESS])
    async def test_one_that_has_not_completed_is_a_conflict(self, client: AsyncClient, status):
        remediation_id = _queue("evil", status, RemediatorStatus.DELAYED)

        response = await client.post(f"/remediation/remediations/{remediation_id}/retry")

        assert response.status_code == 409
        assert _remediation(remediation_id).result == RemediatorStatus.DELAYED.value

    @pytest.mark.asyncio
    async def test_unknown_remediation(self, client: AsyncClient):
        response = await client.post("/remediation/remediations/999999/retry")
        assert response.status_code == 404
        assert response.json()["detail"] == "remediation 999999 not found"


class TestRestore:
    @pytest.mark.asyncio
    async def test_restores_what_that_removal_removed(self, client: AsyncClient):
        """The restore uses the key of the removal it undoes, not of the target's latest one, and is
        the caller's rather than the remover's."""
        other = add_user(username="remover", email="remover@localhost", display_name="remover", password="TestPass123!")
        removal = _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS, restore_key="first-key")
        _set(removal, user_id=other.id)
        _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS, restore_key="later-key")

        response = await client.post(f"/remediation/remediations/{removal}/restore")

        assert response.status_code == 201
        queued = response.json()
        assert (queued["action"], queued["status"]) == ("restore", "NEW")
        restore = _remediation(queued["id"])
        assert (restore.key, restore.restore_key, restore.user_id) == ("evil", "first-key", _caller_id())

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action, status, result", [
        (RemediationAction.REMOVE, RemediationStatus.COMPLETED, RemediatorStatus.FAILED),
        (RemediationAction.REMOVE, RemediationStatus.IN_PROGRESS, RemediatorStatus.DELAYED),
        (RemediationAction.RESTORE, RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS),
    ])
    async def test_only_a_removal_that_succeeded(self, client: AsyncClient, action, status, result):
        remediation_id = _queue("evil", status, result, action=action)

        response = await client.post(f"/remediation/remediations/{remediation_id}/restore")

        assert response.status_code == 409
        assert get_db().query(Remediation).count() == 1


class TestList:
    @pytest.mark.asyncio
    async def test_newest_first_in_pages(self, client: AsyncClient):
        ids = [_queue(f"value-{n}") for n in range(5)]

        first = (await client.get("/remediation/remediations", params={"limit": 2})).json()
        second = (await client.get("/remediation/remediations/", params={"limit": 2, "cursor": first["next_cursor"]})).json()
        third = (await client.get("/remediation/remediations", params={"limit": 2, "cursor": second["next_cursor"]})).json()

        assert [row["id"] for page in (first, second, third) for row in page["data"]] == ids[::-1]
        assert third["next_cursor"] is None

    @pytest.mark.asyncio
    async def test_row(self, client: AsyncClient):
        remediation_id = _queue("evil", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS)

        (row,) = (await client.get("/remediation/remediations")).json()["data"]

        assert row.items() >= {
            "id": remediation_id, "remediator": REMEDIATOR, "observable_type": F_TEST, "observable_value": "evil",
            "action": "remove", "status": "COMPLETED", "result": "SUCCESS", "analyst": "unittest",
        }.items()
        assert row["insert_date"]

    @pytest.mark.asyncio
    async def test_filters(self, client: AsyncClient):
        new = _queue("evil.example")
        failed = _queue("worse.example", RemediationStatus.COMPLETED, RemediatorStatus.FAILED)
        restored = _queue("evil.example", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS,
                          action=RemediationAction.RESTORE)
        old = _queue("old.example", RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS)
        _set(old, insert_date=_utcnow() - timedelta(days=30))

        assert await _ids(client, f"id:{failed},{old}") == [old, failed]
        assert await _ids(client, "value:evil") == [restored, new]
        assert await _ids(client, "status:new,in_progress") == [new]
        assert await _ids(client, "action:restore") == [restored]
        assert await _ids(client, "result:FAILED") == [failed]
        # inverted, a filter also keeps the rows that have no value, such as no result yet
        assert await _ids(client, "!result:SUCCESS") == [failed, new]
        assert await _ids(client, "created:-7d") == [restored, failed, new]
        assert await _ids(client, "analyst:unitt", "remediator:tes") == [old, restored, failed, new]
        assert await _ids(client, "analyst:nobody") == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("params, status", [
        ({"f": "status:done"}, 422),
        ({"f": "id:seven"}, 422),
        ({"f": "colour:red"}, 422),
        ({"tz": "Mars/Olympus"}, 422),
        ({"cursor": "not a cursor"}, 400),
    ])
    async def test_bad_requests(self, client: AsyncClient, params, status):
        assert (await client.get("/remediation/remediations", params=params)).status_code == status

    @pytest.mark.asyncio
    async def test_exports(self, client: AsyncClient):
        first = _queue("evil")
        second = _queue("worse", RemediationStatus.COMPLETED, RemediatorStatus.FAILED)

        ndjson = await client.get("/remediation/remediations/export/ndjson")
        csv_response = await client.get("/remediation/remediations/export/csv", params={"f": "result:failed"})

        assert ndjson.status_code == 200
        assert [json.loads(line)["id"] for line in ndjson.text.splitlines()] == [second, first]
        assert csv_response.status_code == 200
        assert "attachment" in csv_response.headers["content-disposition"]
        (row,) = list(csv.DictReader(io.StringIO(csv_response.text)))
        assert (row["id"], row["observable_value"], row["result"]) == (str(second), "worse", "FAILED")


class TestHistory:
    @pytest.mark.asyncio
    async def test_newest_first(self, client: AsyncClient):
        remediation_id = _queue("evil")
        now = _utcnow().replace(microsecond=0)
        _history(remediation_id, "first try", now - timedelta(minutes=2))
        _history(remediation_id, "second try", now - timedelta(minutes=1))
        _history(remediation_id, "done", now, RemediatorStatus.SUCCESS)
        _history(_queue("other"), "not this one", now)

        response = await client.get(f"/remediation/remediations/{remediation_id}/history")
        limited = await client.get(f"/remediation/remediations/{remediation_id}/history", params={"limit": 1})

        assert response.status_code == 200
        assert [(e["message"], e["result"]) for e in response.json()["data"]] == [
            ("done", "SUCCESS"), ("second try", "DELAYED"), ("first try", "DELAYED")]
        assert [e["message"] for e in limited.json()["data"]] == ["done"]

    @pytest.mark.asyncio
    async def test_unknown_remediation(self, client: AsyncClient):
        assert (await client.get("/remediation/remediations/999999/history")).status_code == 404
