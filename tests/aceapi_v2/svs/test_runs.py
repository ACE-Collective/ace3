"""POST /api/v2/svs/runs, the launcher's lifecycle calls (docs/SVS_API.md, *Runs*)."""

from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Alert, SVSAttribution, SVSRun
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs.hosts import build_spec, create_host
from saq.svs.markers import MARKER_REGEX
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LINUX_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
SIGNATURE = "5c1a9e57-0000-4000-8000-00000000a7a7"

REGISTRATION = {"test_guid": GUID, "targets": [{"hostname": "win10-01.lab.example", "username": "LAB\\svc_art"}],
                "launcher": "art", "batch_id": "nightly", "extra": {"ticket": 42}}


@pytest.fixture(autouse=True)
def setup(no_hunts):
    add_catalog_test(GUID)
    add_catalog_test(LINUX_GUID, platforms=("linux",))
    create_host(build_spec("win10-01.lab.example", usernames=["svc_art"], platform="windows"), None)


async def _register(client: AsyncClient, **values) -> dict:
    response = await client.post("/svs/runs/", json={**REGISTRATION, **values})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_the_lifecycle(client: AsyncClient):
    run = await _register(client)
    assert run["state"] == "created" and MARKER_REGEX.fullmatch(run["marker"])
    assert run["platform"] == "windows"
    assert (run["observation_seconds"], run["attribution_seconds"]) == (3600, 25 * 3600)
    assert run["targets"] == [{"hostname": "win10-01.lab.example", "username": "LAB\\svc_art", "host": "win10-01",
                               "fqdn": "win10-01.lab.example", "user": "svc_art"}]

    response = await client.post(f"/svs/runs/{run['run_id']}/start")
    assert response.status_code == 200, response.text
    started = response.json()
    assert started["state"] == "started" and started["observation_ends_at"] is not None

    response = await client.post(f"/svs/runs/{run['run_id']}/executed", json={"exit_code": 0})
    assert response.status_code == 200 and response.json()["state"] == "started"

    response = await client.post(f"/svs/runs/{run['run_id']}/cancel")
    assert response.status_code == 200 and response.json()["state"] == "canceled"


@pytest.mark.asyncio
@pytest.mark.usefixtures("overlapping_runs")
async def test_a_reported_failure_and_a_cancel_before_start(client: AsyncClient):
    run = await _register(client)
    await client.post(f"/svs/runs/{run['run_id']}/start")
    response = await client.post(f"/svs/runs/{run['run_id']}/executed", json={"exit_code": 0, "error": "missing prereq"})
    assert response.json()["state"] == "error" and "missing prereq" in response.json()["error_reason"]

    run = await _register(client)
    response = await client.post(f"/svs/runs/{run['run_id']}/cancel")
    assert (response.json()["state"], response.json()["close_reason"]) == ("closed", "canceled before start")


@pytest.mark.asyncio
async def test_conflicts_and_unknown_runs(client: AsyncClient):
    run = await _register(client)
    response = await client.post(f"/svs/runs/{run['run_id']}/executed", json={"exit_code": 0})
    assert response.status_code == 409 and response.json()["detail"]["state"] == "created"

    await client.post(f"/svs/runs/{run['run_id']}/start")
    response = await client.post(f"/svs/runs/{run['run_id']}/start")
    assert response.status_code == 409 and response.json()["detail"]["state"] == "started"

    missing = "00000000-0000-4000-8000-000000000000"
    assert (await client.post(f"/svs/runs/{missing}/start")).status_code == 404
    assert (await client.post(f"/svs/runs/{missing}/cancel")).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("values, message", [
    ({"test_guid": "dddddddd-4444-4444-8444-444444444444"}, "is not in the catalog"),
    ({"test_guid": LINUX_GUID}, "test host win10-01 is windows"),
    ({"extra": {"blob": "x" * 20000}}, "larger than 16384 bytes"),
])
async def test_invalid_registrations(client: AsyncClient, values, message):
    response = await client.post("/svs/runs/", json={**REGISTRATION, **values})
    assert response.status_code == 422 and message in response.json()["detail"]


@pytest.mark.asyncio
async def test_the_request_is_validated(client: AsyncClient):
    assert (await client.post("/svs/runs/", json={**REGISTRATION, "targets": []})).status_code == 422
    assert (await client.post("/svs/runs/", json={**REGISTRATION, "extra": "text"})).status_code == 422
    assert (await client.post("/svs/runs/", json={k: v for k, v in REGISTRATION.items() if k != "launcher"})).status_code == 422


@pytest.mark.asyncio
async def test_a_registration_against_a_non_test_host_is_refused_and_alerts(client: AsyncClient):
    response = await client.post("/svs/runs/", json={**REGISTRATION, "targets": [{"hostname": "prod-dc-01"}]})
    assert response.status_code == 403
    assert response.json()["detail"]["reasons"] == ["prod-dc-01 is not a test host"]

    db = get_db()
    db.expire_all()
    assert db.execute(select(SVSRun)).first() is None
    (alert,) = db.query(Alert).all()
    assert alert.queue == "default"

    # the second refusal within the hour is only logged
    assert (await client.post("/svs/runs/", json={**REGISTRATION, "targets": [{"hostname": "prod-dc-01"}]})).status_code == 403
    db.expire_all()
    assert len(db.query(Alert).all()) == 1


@pytest.mark.asyncio
async def test_validate_answers_what_registering_would_and_writes_nothing(client: AsyncClient):
    response = await client.post("/svs/runs/validate", json=REGISTRATION)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "decision": "accepted", "status_code": 201, "message": None, "platform": "windows",
        "observation_seconds": 3600, "observation_source": "all_hunts", "attribution_seconds": 25 * 3600,
        "holds_host": False,
        "targets": [{"hostname": "win10-01.lab.example", "username": "LAB\\svc_art", "accepted": True, "reason": None,
                     "test_host": "win10-01", "platform": "windows", "held_by": []}]}

    response = await client.post("/svs/runs/validate", json={**REGISTRATION, "targets": [
        {"hostname": "prod-dc-01"}, {"hostname": "win10-01", "username": "administrator"}]})
    assert response.status_code == 200, response.text
    validation = response.json()
    assert (validation["decision"], validation["status_code"], validation["platform"]) == ("refused", 403, None)
    assert [(t["accepted"], t["reason"], t["test_host"]) for t in validation["targets"]] == [
        (False, "prod-dc-01 is not a test host", None),
        (False, "administrator is not a user of test host win10-01", "win10-01")]

    response = await client.post("/svs/runs/validate", json={**REGISTRATION, "test_guid": LINUX_GUID})
    validation = response.json()
    assert (validation["decision"], validation["status_code"]) == ("invalid", 422)
    assert "test host win10-01 is windows" in validation["message"]

    db = get_db()
    db.expire_all()
    assert db.execute(select(SVSRun)).first() is None
    assert db.query(Alert).all() == []

    # the body is checked as registering checks it
    assert (await client.post("/svs/runs/validate", json={**REGISTRATION, "targets": []})).status_code == 422


@pytest.mark.asyncio
async def test_a_host_held_by_another_run_is_409(client: AsyncClient):
    first = await _register(client)
    assert first["holds_host"] is False

    response = await client.post("/svs/runs/", json=REGISTRATION)
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["holders"] == [{"host": "win10-01", "run_id": first["run_id"], "state": "created", "until": None}]
    assert first["run_id"] in detail["message"]

    response = await client.post("/svs/runs/validate", json=REGISTRATION)
    validation = response.json()
    assert (validation["decision"], validation["status_code"], validation["platform"]) == ("host_busy", 409, "windows")
    assert [h["run_id"] for h in validation["targets"][0]["held_by"]] == [first["run_id"]]

    # no alert: a lifecycle conflict, not a refusal
    db = get_db()
    db.expire_all()
    assert db.query(Alert).all() == []


@pytest.mark.asyncio
async def test_start_answers_409_when_another_run_holds_the_host(client: AsyncClient, monkeypatch):
    from saq.svs import runs
    # runs registered before one run per host was enforced
    monkeypatch.setattr(runs, "host_holders", lambda *args, **kwargs: [])
    first = await _register(client)
    await client.post(f"/svs/runs/{first['run_id']}/start")
    second = await _register(client)
    monkeypatch.undo()

    response = await client.post(f"/svs/runs/{second['run_id']}/start")
    assert response.status_code == 409, response.text
    (holder,) = response.json()["detail"]["holders"]
    assert (holder["run_id"], holder["state"]) == (first["run_id"], "started") and holder["until"] is not None


@pytest.mark.asyncio
async def test_cleanup(client: AsyncClient):
    run = await _register(client)
    assert (await client.post(f"/svs/runs/{run['run_id']}/cleanup")).status_code == 409
    await client.post(f"/svs/runs/{run['run_id']}/start")

    response = await client.post(f"/svs/runs/{run['run_id']}/cleanup")
    assert response.status_code == 200, response.text
    cleanup_at = datetime.fromisoformat(response.json()["cleanup_at"])
    assert (await client.post(f"/svs/runs/{run['run_id']}/cleanup")).status_code == 409

    # an attribution of the cleanup, and one of the test
    run_db_id = get_db().execute(select(SVSRun.id).where(SVSRun.uuid == run["run_id"])).scalar_one()
    with private_transaction() as session:
        for alert_uuid, event_time in (("aaaaaaaa-0000-4000-8000-000000000001", cleanup_at + timedelta(seconds=5)),
                                       ("aaaaaaaa-0000-4000-8000-000000000002", cleanup_at - timedelta(seconds=5))):
            session.add(SVSAttribution(run_id=run_db_id, alert_uuid=alert_uuid, content_hash="0" * 64,
                                       signature_uuid=SIGNATURE, confidence="marker", source="router", actor="svs",
                                       created_at=datetime.now(), event_time=event_time))

    attributions = (await client.get(f"/svs/runs/{run['run_id']}/attributions")).json()["data"]
    assert [(a["alert_uuid"][-1], a["cleanup"]) for a in attributions] == [("1", True), ("2", False)]
    assert attributions[0]["event_time"] is not None
    alerts = (await client.get(f"/svs/runs/{run['run_id']}/alerts")).json()["data"]
    assert [(a["alert_uuid"][-1], a["cleanup"]) for a in alerts] == [("1", True), ("2", False)]
    assert (await client.get(f"/svs/runs/{run['run_id']}")).json()["cleanup_at"] == response.json()["cleanup_at"]


@pytest.mark.asyncio
async def test_every_call_needs_run_register(_override_db_session, session: AsyncSession, test_user):
    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        assert (await client.post("/svs/runs/", json=REGISTRATION)).status_code == 403
        assert (await client.post("/svs/runs/validate", json=REGISTRATION)).status_code == 403

    launcher = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_register")])
    async with api_key_client(launcher) as client:
        assert (await client.post("/svs/runs/validate", json=REGISTRATION)).status_code == 200
        run = await _register(client)
        assert (await client.post(f"/svs/runs/{run['run_id']}/start")).status_code == 200


@pytest.mark.asyncio
async def test_no_permission(noperm_client: AsyncClient):
    assert (await noperm_client.post("/svs/runs/", json=REGISTRATION)).status_code == 403
