"""/api/v2/remediation: the alert pages' remediation dialog."""

import logging
import uuid

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
            assert (await reader.delete(f"/remediation/remediations/{remediation_id}")).status_code == 403

        assert get_db().query(Remediation).count() == 1

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
