"""A person's actions on runs through the API (docs/SVS_API.md, *Run actions*): bulk take-ownership,
cancel and close, review, and comments."""

import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.runs import service
from aceapi_v2.svs.runs.schemas import BulkRunRequest
from saq.alert_routing import reset_alert_routers
from saq.constants import F_HOSTNAME
from saq.database.model import SVSRun
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.database.util.user_management import add_user
from saq.svs import runs, signatures, windows
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
RULE = "22222222-bbbb-4bbb-8bbb-222222222222"


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.setattr(windows, "hunt_info", lambda: {})
    monkeypatch.setattr(signatures, "_yara_signatures", lambda: {})
    reset_alert_routers()
    monkeypatch.setattr("saq.database.util.alert.submit_payload_task", lambda alert_uuid: None)
    monkeypatch.setattr("saq.database.util.alert.submit_index_task", lambda alert_uuid: None)
    add_catalog_test(GUID)
    add_test_host("win10-01")
    yield
    reset_alert_routers()


def _ended(signature_uuid=None) -> SVSRun:
    run = started_run(GUID, now=datetime.now() - timedelta(hours=3))
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now() - timedelta(hours=2))
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, "win10-01")
    root.details = {"cmd": run.marker}
    root.add_detection_point("hunt hit", signature_uuid=signature_uuid)
    root.save()
    ALERT(root)
    runs.run_timers(now=run.observation_ends_at + timedelta(seconds=1))
    return run


@pytest.mark.asyncio
async def test_review(client: AsyncClient, test_user):
    run = _ended(RULE)
    response = await client.post(f"/svs/runs/{run.uuid}/review")
    assert response.status_code == 409
    assert response.json()["detail"]["candidates"] == [RULE]

    await client.put(f"/svs/tests/{GUID}/expectations/{RULE}", json={"state": "expected"})
    response = await client.post(f"/svs/runs/{run.uuid}/review")
    assert response.status_code == 409 and response.json()["detail"]["stale"] is True
    runs.run_timers()

    response = await client.post(f"/svs/runs/{run.uuid}/review", json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["re_review"], body["counts"], body["alerts_closed"]) == (False, {"hit": 1}, 1)
    assert (body["run"]["state"], body["run"]["reviewer"], body["run"]["owner"]) == (
        "reviewed", test_user.username, test_user.username)

    assert (await client.post(f"/svs/runs/{uuid.uuid4()}/review")).status_code == 404
    started = started_run(GUID)
    response = await client.post(f"/svs/runs/{started.uuid}/review")
    assert response.status_code == 409 and response.json()["detail"]["state"] == "started"


@pytest.mark.asyncio
async def test_review_takes_from_a_confirmed_owner(client: AsyncClient):
    run = _ended()
    bob = add_user("bob", "bob@localhost", "Bob", "bob")
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(owner_id=bob.id))
    db.commit()

    response = await client.post(f"/svs/runs/{run.uuid}/review")
    assert response.status_code == 409 and response.json()["detail"]["owner"] == "bob"
    response = await client.post(f"/svs/runs/{run.uuid}/review", json={"confirmed_take_from": "bob"})
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_bulk_actions(client: AsyncClient, test_user):
    ended, started = _ended(), started_run(GUID)
    bob = add_user("bob", "bob@localhost", "Bob", "bob")
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == started.id).values(owner_id=bob.id))
    db.commit()

    response = await client.post("/svs/runs/bulk/take-ownership", json={"run_ids": [ended.uuid, started.uuid]})
    assert response.status_code == 200, response.text
    assert response.json() == {"done": [ended.uuid], "left_alone": {started.uuid: "bob"}, "conflicts": {},
                               "unknown": []}

    response = await client.post("/svs/runs/bulk/cancel", json={
        "run_ids": [started.uuid, ended.uuid], "confirmed_takes": {started.uuid: "bob"}})
    body = response.json()
    assert body["done"] == [started.uuid] and ended.uuid in body["conflicts"]

    response = await client.post("/svs/runs/bulk/close", json={"run_ids": [ended.uuid, started.uuid]})
    body = response.json()
    assert body["done"] == [started.uuid] and "needs a reason" in body["conflicts"][ended.uuid]
    response = await client.post("/svs/runs/bulk/close", json={"run_ids": [ended.uuid], "reason": "a bad run"})
    assert response.json()["done"] == [ended.uuid]
    detail = (await client.get(f"/svs/runs/{ended.uuid}")).json()
    assert (detail["state"], detail["close_reason"], detail["owner"]) == ("closed", "a bad run", test_user.username)

    assert (await client.post("/svs/runs/bulk/close", json={"run_ids": ["not-a-uuid"]})).status_code == 400
    assert (await client.post("/svs/runs/bulk/close", json={"run_ids": []})).status_code == 422


@pytest.mark.asyncio
async def test_left_alone_is_a_confirmation(client: AsyncClient, test_user):
    """What a bulk action leaves alone, sent back as it is, confirms taking those runs: the GUI's
    take-from-owner dialog relies on it, for an owner whose display name isn't their username too."""
    run = started_run(GUID)
    carol = add_user("carol", "carol@localhost", "Carol Example", "carol")
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(owner_id=carol.id))
    db.commit()

    left_alone = (await client.post("/svs/runs/bulk/take-ownership", json={"run_ids": [run.uuid]})).json()["left_alone"]
    assert left_alone == {run.uuid: "carol"}
    response = await client.post("/svs/runs/bulk/take-ownership", json={
        "run_ids": list(left_alone), "confirmed_takes": left_alone})
    assert response.json()["done"] == [run.uuid]
    assert (await client.get(f"/svs/runs/{run.uuid}")).json()["owner"] == test_user.username


@pytest.mark.asyncio
async def test_comments(client: AsyncClient, test_user):
    run = started_run(GUID)
    response = await client.post(f"/svs/runs/{run.uuid}/comments", json={"comment": "agent restarted mid-run"})
    assert response.status_code == 201, response.text
    comment = response.json()
    assert (comment["user"], comment["run_id"]) == (test_user.username, run.uuid)

    response = await client.patch(f"/svs/runs/{run.uuid}/comments/{comment['id']}", json={"comment": "rerun it"})
    assert response.status_code == 200 and response.json()["comment"] == "rerun it"
    assert [c["comment"] for c in (await client.get(f"/svs/runs/{run.uuid}/comments")).json()] == ["rerun it"]
    assert (await client.post(f"/svs/runs/{run.uuid}/comments", json={"comment": "   "})).status_code == 422
    assert (await client.delete(f"/svs/runs/{run.uuid}/comments/{comment['id']}")).status_code == 204
    assert (await client.delete(f"/svs/runs/{run.uuid}/comments/{comment['id']}")).status_code == 404
    assert (await client.get(f"/svs/runs/{uuid.uuid4()}/comments")).status_code == 404


@pytest.mark.asyncio
async def test_permissions(_override_db_session, session: AsyncSession, test_user):
    run = started_run(GUID)
    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        assert (await client.get(f"/svs/runs/{run.uuid}/comments")).status_code == 200
        assert (await client.post(f"/svs/runs/{run.uuid}/comments", json={"comment": "x"})).status_code == 403
        assert (await client.post(f"/svs/runs/{run.uuid}/review")).status_code == 403
        for action in ("take-ownership", "cancel", "close"):
            assert (await client.post(f"/svs/runs/bulk/{action}", json={"run_ids": [run.uuid]})).status_code == 403

    manager = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_manage")])
    async with api_key_client(manager) as client:
        assert (await client.post(f"/svs/runs/{run.uuid}/comments", json={"comment": "x"})).status_code == 201
        assert (await client.post("/svs/runs/bulk/take-ownership", json={"run_ids": [run.uuid]})).status_code == 200


def test_a_config_key_is_refused():
    with pytest.raises(HTTPException) as e:
        service.take_runs(BulkRunRequest(run_ids=[str(uuid.uuid4())]), None, "ci")
    assert e.value.status_code == 422
