"""A person's association changes and the attributions through the API (docs/SVS_API.md,
*Attributions*): POST /svs/runs/{run_id}/alerts/{alert_uuid}/associate|disassociate|not-a-test|keep,
GET /svs/runs/{run_id}/attributions and the feed, GET /svs/runs/attributions."""

import csv
import io
import json
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.runs import service
from saq.alert_routing import reset_alert_routers
from saq.configuration.config import get_config
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
    add_catalog_test(GUID)
    add_test_host("win10-01")
    yield
    reset_alert_routers()


@pytest.fixture
def no_settle(monkeypatch):
    monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 0)


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
async def test_associate_and_disassociate(client: AsyncClient, test_user):
    run = _run()
    alert_uuid = _alert(host="srv-01")

    response = await client.post(f"/svs/runs/{run.uuid}/alerts/{alert_uuid}/associate", json={"reason": "seen live"})
    assert response.status_code == 200, response.text
    assert response.json() == {"alert_uuid": alert_uuid, "svs_status": "test", "queue": get_config().svs.queue,
                               "moved": True, "reopened": False}

    (row,) = (await client.get(f"/svs/runs/{run.uuid}/attributions")).json()["data"]
    assert (row["alert_uuid"], row["source"], row["confidence"], row["actor_user"]) == (
        alert_uuid, "manual", "marker", test_user.username)

    response = await client.post(f"/svs/runs/{run.uuid}/alerts/{alert_uuid}/disassociate", json={"reason": "wrong run"})
    assert response.status_code == 200, response.text
    assert (response.json()["queue"], response.json()["svs_status"]) == (QUEUE_DEFAULT, None)
    (row,) = (await client.get(f"/svs/runs/{run.uuid}/attributions")).json()["data"]
    assert (row["removed_by_user"], row["removal_reason"]) == (test_user.username, "wrong run")
    # the body is optional
    assert (await client.post(f"/svs/runs/{run.uuid}/alerts/{alert_uuid}/associate")).status_code == 200


@pytest.mark.asyncio
async def test_keep_and_not_a_test(client: AsyncClient):
    run = _run()
    kept, rejected = _alert(), _alert()
    response = await client.post(f"/svs/runs/{run.uuid}/alerts/{kept}/keep")
    assert response.status_code == 200 and response.json()["svs_status"] == "test?"
    response = await client.post(f"/svs/runs/{run.uuid}/alerts/{rejected}/not-a-test", json={})
    assert response.status_code == 200 and response.json()["svs_status"] is None

    rows = {row["alert_uuid"]: row for row in (await client.get(f"/svs/runs/{run.uuid}/attributions")).json()["data"]}
    assert rows[kept]["kept_at"] and rows[kept]["kept_by_user"]
    assert rows[rejected]["removal_reason"] == "not a test"


@pytest.mark.asyncio
async def test_errors(client: AsyncClient):
    run = _run()
    marked = _alert(marker=run.marker)
    base = f"/svs/runs/{run.uuid}/alerts"
    assert (await client.post(f"{base}/{marked}/not-a-test")).status_code == 409
    assert (await client.post(f"{base}/{marked}/keep")).status_code == 409
    assert (await client.post(f"{base}/{_alert(host='srv-01')}/disassociate")).status_code == 409
    assert (await client.post(f"{base}/{insert_alert().uuid}/associate")).status_code == 422
    assert (await client.post(f"{base}/{uuid.uuid4()}/associate")).status_code == 404
    assert (await client.post(f"/svs/runs/{uuid.uuid4()}/alerts/{marked}/associate")).status_code == 404
    assert (await client.post(f"{base}/not-a-uuid/associate")).status_code == 400


def test_a_config_key_is_refused():
    with pytest.raises(HTTPException) as e:
        service.change_association("associate", str(uuid.uuid4()), str(uuid.uuid4()), None, None, "ci")
    assert e.value.status_code == 422


@pytest.mark.asyncio
async def test_permissions(_override_db_session, session: AsyncSession, test_user):
    run = _run()
    alert_uuid = _alert(host="srv-01")
    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        assert (await client.get(f"/svs/runs/{run.uuid}/attributions")).status_code == 200
        for action in ("associate", "disassociate", "not-a-test", "keep"):
            assert (await client.post(f"/svs/runs/{run.uuid}/alerts/{alert_uuid}/{action}")).status_code == 403

    manager = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_manage")])
    async with api_key_client(manager) as client:
        assert (await client.post(f"/svs/runs/{run.uuid}/alerts/{alert_uuid}/associate")).status_code == 200
        assert (await client.get(f"/svs/runs/{run.uuid}/attributions")).status_code == 403


@pytest.mark.asyncio
async def test_the_feed_and_exports(client: AsyncClient, no_settle):
    run, other = _run(), _run()
    mine = _alert(marker=run.marker)
    _alert(marker=other.marker)

    rows = (await client.get("/svs/runs/attributions")).json()["data"]
    assert {row["run_id"] for row in rows} == {run.uuid, other.uuid}
    rows = (await client.get("/svs/runs/attributions", params={"f": "batch:none"})).json()["data"]
    assert rows == []
    first = (await client.get("/svs/runs/attributions", params={"limit": 1})).json()
    second = (await client.get("/svs/runs/attributions", params={"limit": 1, "cursor": first["next_cursor"]})).json()
    assert len(first["data"]) == len(second["data"]) == 1
    future = (await client.get("/svs/runs/attributions", params={"changed_since": "2099-01-01T00:00:00Z"})).json()
    assert future["data"] == []

    lines = (await client.get(f"/svs/runs/{run.uuid}/attributions/export/ndjson")).text.splitlines()
    assert [json.loads(line)["alert_uuid"] for line in lines] == [mine]
    records = list(csv.DictReader(io.StringIO((await client.get("/svs/runs/attributions/export/csv")).text)))
    assert len(records) == 2


@pytest.mark.asyncio
async def test_the_feed_waits_for_rows_to_settle(client: AsyncClient):
    run = _run()
    _alert(marker=run.marker)
    assert (await client.get("/svs/runs/attributions")).json()["data"] == []
