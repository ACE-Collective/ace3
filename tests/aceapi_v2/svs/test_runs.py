"""POST /api/v2/svs/runs, the launcher's lifecycle calls (docs/SVS_API.md, *Runs*)."""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.database.model import Alert, SVSRun
from saq.database.pool import get_db
from saq.svs.hosts import build_spec, create_host
from saq.svs.markers import MARKER_REGEX
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LINUX_GUID = "bbbbbbbb-2222-4222-8222-222222222222"

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
async def test_every_call_needs_run_register(_override_db_session, session: AsyncSession, test_user):
    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        assert (await client.post("/svs/runs/", json=REGISTRATION)).status_code == 403

    launcher = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_register")])
    async with api_key_client(launcher) as client:
        run = await _register(client)
        assert (await client.post(f"/svs/runs/{run['run_id']}/start")).status_code == 200


@pytest.mark.asyncio
async def test_no_permission(noperm_client: AsyncClient):
    assert (await noperm_client.post("/svs/runs/", json=REGISTRATION)).status_code == 403
