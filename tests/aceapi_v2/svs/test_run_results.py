"""A run's result through the API (docs/SVS_API.md, *Results*): GET /svs/runs/{run_id}/results and
the result feed over every run, GET /svs/runs/results."""

import csv
import io
import json
import uuid
from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import update

from aceapi_v2.svs.runs import service
from saq.database.model import SVSAttribution, SVSRun
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs import results
from saq.svs.result_state import mark_runs_stale
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run

# several runs on one test host are fixtures here; the host's claim is tested in test_runs.py
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("overlapping_runs")]

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
OTHER_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
SIGNATURE = "22222222-bbbb-4bbb-8bbb-222222222222"
NOISE = "33333333-cccc-4ccc-8ccc-333333333333"


@pytest.fixture(autouse=True)
def setup(no_hunts, yara_dir):
    add_catalog_test(GUID)
    add_catalog_test(OTHER_GUID)
    add_test_host("win10-01")


@pytest.fixture
def no_settle(monkeypatch):
    monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 0)


def _ended_run(test_guid: str = GUID, *signature_uuids: str) -> SVSRun:
    run = started_run(test_guid, now=datetime.now() - timedelta(hours=2))
    with private_transaction() as session:
        for signature_uuid in signature_uuids:
            session.add(SVSAttribution(
                run_id=run.id, alert_uuid=str(uuid.uuid4()), content_hash=uuid.uuid4().hex * 2,
                signature_uuid=signature_uuid, signature_family="yara", confidence="marker", source="router",
                actor="svs", created_at=datetime.now()))
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(state="ended", ended_at=datetime.now()))
    db.commit()
    results.compute_result(run.id)
    return run


@pytest.mark.asyncio
async def test_a_runs_result(client: AsyncClient):
    run = _ended_run(GUID, SIGNATURE, NOISE)

    body = (await client.get(f"/svs/runs/{run.uuid}/results")).json()
    assert {(row["signature_uuid"], row["status"]) for row in body["data"]} == {
        (SIGNATURE, "candidate"), (NOISE, "candidate")}
    row = body["data"][0]
    assert (row["run_id"], row["alert_count"], row["signature_family"], row["reviewed_status"]) == (
        run.uuid, 1, "yara", None)
    assert body["stale"] is False and body["computed_at"]

    with private_transaction() as session:
        mark_runs_stale(session, run_ids=[run.id])
    assert (await client.get(f"/svs/runs/{run.uuid}/results")).json()["stale"] is True

    first = (await client.get(f"/svs/runs/{run.uuid}/results", params={"limit": 1})).json()
    second = (await client.get(f"/svs/runs/{run.uuid}/results",
                               params={"limit": 1, "cursor": first["next_cursor"]})).json()
    assert len(first["data"]) == len(second["data"]) == 1 and second["next_cursor"] is None

    lines = (await client.get(f"/svs/runs/{run.uuid}/results/export/ndjson")).text.splitlines()
    assert {json.loads(line)["signature_uuid"] for line in lines} == {SIGNATURE, NOISE}
    records = list(csv.DictReader(io.StringIO((await client.get(f"/svs/runs/{run.uuid}/results/export/csv")).text)))
    assert {record["status"] for record in records} == {"candidate"}


@pytest.mark.asyncio
async def test_a_run_without_a_result(client: AsyncClient):
    run = started_run(GUID)
    body = (await client.get(f"/svs/runs/{run.uuid}/results")).json()
    assert (body["data"], body["stale"], body["computed_at"]) == ([], False, None)
    assert (await client.get(f"/svs/runs/{uuid.uuid4()}/results")).status_code == 404
    assert (await client.get("/svs/runs/not-a-uuid/results")).status_code == 400


@pytest.mark.asyncio
async def test_the_feed_takes_the_runs_filters(client: AsyncClient, no_settle):
    mine = _ended_run(GUID, SIGNATURE)
    _ended_run(OTHER_GUID, NOISE)

    rows = (await client.get("/svs/runs/results")).json()["data"]
    assert {row["signature_uuid"] for row in rows} == {SIGNATURE, NOISE}
    rows = (await client.get("/svs/runs/results", params={"f": f"test:{GUID}"})).json()["data"]
    assert [(row["run_id"], row["signature_uuid"]) for row in rows] == [(mine.uuid, SIGNATURE)]

    first = (await client.get("/svs/runs/results", params={"limit": 1})).json()
    second = (await client.get("/svs/runs/results", params={"limit": 1, "cursor": first["next_cursor"]})).json()
    assert {first["data"][0]["signature_uuid"], second["data"][0]["signature_uuid"]} == {SIGNATURE, NOISE}
    assert first["stale"] is None

    future = (await client.get("/svs/runs/results", params={"changed_since": "2099-01-01T00:00:00Z"})).json()
    assert future["data"] == []
    assert (await client.get("/svs/runs/results", params={"f": "nope:x"})).status_code == 422

    assert len((await client.get("/svs/runs/results/export/ndjson")).text.splitlines()) == 2
    records = list(csv.DictReader(io.StringIO((await client.get("/svs/runs/results/export/csv")).text)))
    assert len(records) == 2


@pytest.mark.asyncio
async def test_the_feed_waits_for_rows_to_settle(client: AsyncClient):
    _ended_run(GUID, SIGNATURE)
    assert (await client.get("/svs/runs/results")).json()["data"] == []


@pytest.mark.asyncio
async def test_no_permission(noperm_client: AsyncClient):
    assert (await noperm_client.get("/svs/runs/results")).status_code == 403
    assert (await noperm_client.get(f"/svs/runs/{uuid.uuid4()}/results")).status_code == 403
