"""One alert's side of SVS through the API (docs/SVS_API.md, *An alert's SVS status*): GET
/alerts/{uuid}/svs, and POST /alerts/{uuid}/svs/disassociate|not-a-test, which give a test alert
back to analysts with alert:write."""

import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.auth.utils import API_AUTH_TYPE_CONFIG
from aceapi_v2.svs.alerts import service
from saq.alert_routing import reset_alert_routers
from saq.constants import F_HOSTNAME, QUEUE_DEFAULT
from saq.database.util.alert import ALERT
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import create_root_analysis, insert_alert
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"


@pytest.fixture(autouse=True)
def setup(no_hunts):
    reset_alert_routers()
    add_catalog_test(GUID, name="PowerShell download")
    add_test_host("win10-01")
    yield
    reset_alert_routers()


def _alert(*, marker=None, host="win10-01") -> str:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now())
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    if marker:
        root.details = {"cmd": marker}
    root.add_detection_point("hunt hit")
    root.save()
    ALERT(root)
    return root.uuid


def _run():
    return started_run(GUID, now=datetime.now() - timedelta(minutes=1))


@pytest.mark.asyncio
async def test_what_svs_makes_of_an_alert(client: AsyncClient):
    run = _run()
    alert_uuid = _alert(marker=run.marker)

    response = await client.get(f"/alerts/{alert_uuid}/svs")
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["alert_uuid"], body["svs_status"], body["mismatches"]) == (alert_uuid, "test", [])
    assert body["runs"] == [{"run_id": run.uuid, "state": "started", "test_guid": GUID,
                             "test_name": "PowerShell download"}]
    (detection,) = body["detections"]
    assert detection["run_ids"] == [run.uuid]

    untouched = (await client.get(f"/alerts/{insert_alert().uuid}/svs")).json()
    assert (untouched["svs_status"], untouched["runs"], untouched["detections"]) == (None, [], [])

    assert (await client.get(f"/alerts/{uuid.uuid4()}/svs")).status_code == 404
    assert (await client.get("/alerts/not-a-uuid/svs")).status_code == 400


@pytest.mark.asyncio
async def test_disassociate(client: AsyncClient):
    run = _run()
    alert_uuid = _alert(marker=run.marker)
    assert (await client.get(f"/alerts/{alert_uuid}/svs")).json()["svs_status"] == "test"

    response = await client.post(f"/alerts/{alert_uuid}/svs/disassociate", json={"reason": "a real attack"})
    assert response.status_code == 200, response.text
    assert response.json() == {"alert_uuid": alert_uuid, "run_ids": [run.uuid], "svs_status": None,
                               "queue": QUEUE_DEFAULT, "moved": True, "reopened": False}
    assert (await client.get(f"/alerts/{alert_uuid}/svs")).json()["svs_status"] is None

    # nothing holds it any more
    assert (await client.post(f"/alerts/{alert_uuid}/svs/disassociate")).status_code == 409


@pytest.mark.asyncio
async def test_not_a_test(client: AsyncClient):
    run = _run()
    marked = _alert(marker=run.marker)
    assert (await client.post(f"/alerts/{marked}/svs/not-a-test")).status_code == 409

    context = _alert()
    response = await client.post(f"/alerts/{context}/svs/not-a-test")
    assert response.status_code == 200, response.text
    assert (response.json()["run_ids"], response.json()["svs_status"]) == ([run.uuid], None)


@pytest.mark.asyncio
async def test_errors(client: AsyncClient):
    assert (await client.post(f"/alerts/{uuid.uuid4()}/svs/disassociate")).status_code == 404
    assert (await client.post("/alerts/not-a-uuid/svs/disassociate")).status_code == 400


def test_a_config_key_is_refused():
    with pytest.raises(HTTPException) as e:
        service.disassociate_alert(str(uuid.uuid4()), None, ApiAuthResult(auth_type=API_AUTH_TYPE_CONFIG, auth_name="ci"), False)
    assert e.value.status_code == 422


@pytest.mark.asyncio
async def test_permissions(_override_db_session, session: AsyncSession, test_user):
    run = _run()
    alert_uuid = _alert(marker=run.marker)

    # svs:run_manage is not what gives an alert back from the alert's side
    for scope in ([("alert", "read")], [("svs", "run_manage")]):
        key = await make_api_key(session, test_user.id, inherit=False, scope=scope)
        async with api_key_client(key) as client:
            for action in ("disassociate", "not-a-test"):
                assert (await client.post(f"/alerts/{alert_uuid}/svs/{action}")).status_code == 403, (scope, action)

    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("alert", "read")])
    async with api_key_client(reader) as client:
        assert (await client.get(f"/alerts/{alert_uuid}/svs")).status_code == 200

    writer = await make_api_key(session, test_user.id, inherit=False, scope=[("alert", "write")])
    async with api_key_client(writer) as client:
        assert (await client.get(f"/alerts/{alert_uuid}/svs")).status_code == 403
        response = await client.post(f"/alerts/{alert_uuid}/svs/disassociate")
        assert response.status_code == 200, response.text
        assert response.json()["queue"] == QUEUE_DEFAULT
