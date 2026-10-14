"""GET /api/v2/svs/runs, the runs, their event logs and the event feed (docs/SVS_API.md, *Runs*)."""

import csv
import io
import json
from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.runs import service
from saq.database.model import SVSRun
from saq.database.pool import get_db
from saq.svs import runs, windows
from saq.svs.hosts import build_spec, create_host
from saq.svs.refusals import Caller
from saq.svs.runs import Registration, TargetSpec
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LINUX_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
UNKNOWN_RUN = "dddddddd-4444-4444-8444-444444444444"


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    # no enabled hunts: the observation window is the floor
    monkeypatch.setattr(windows, "hunt_latencies", lambda: {})
    add_catalog_test(GUID)
    add_catalog_test(LINUX_GUID, platforms=("linux",), technique="T1003", name="Dump credentials")
    create_host(build_spec("win10-01.lab.example", usernames=["svc_art"], platform="windows"), None)
    create_host(build_spec("lnx-01", platform="linux"), None)


@pytest.fixture
def no_settle(monkeypatch):
    """Lets the (updated_at, id) listings return rows written a moment ago (the settle window is
    tested on its own)."""
    monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 0)


def _caller(user_id=None) -> Caller:
    return Caller(name="art-launcher", user_id=user_id, address="10.1.2.3")


def _register(created_at: datetime, *, guid=GUID, host="win10-01.lab.example", username="LAB\\svc_art",
              launcher="art", batch_id="nightly", user_id=None) -> str:
    registration = Registration(test_guid=guid, targets=[TargetSpec(host, username)], launcher=launcher,
                                batch_id=batch_id, extra={"ticket": 42})
    return runs.register(registration, _caller(user_id), now=created_at).uuid


def _set(run_uuid: str, **values) -> None:
    # the states and columns PR10's review and ownership write
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.uuid == run_uuid).values(**values))
    db.commit()


@pytest.fixture
def seeded(test_user) -> dict[str, str]:
    """One run in each state that matters to the screen, created an hour apart, oldest first."""
    now = datetime.now()
    at = lambda hours: now - timedelta(hours=hours)  # noqa: E731
    seeded = {}
    seeded["created"] = _register(at(72))
    seeded["started"] = _register(at(6), guid=LINUX_GUID, host="lnx-01", username=None, launcher="caldera-bridge",
                                  batch_id=None)
    runs.start(seeded["started"], _caller(), now=at(5.5))
    seeded["ended"] = _register(at(5))
    runs.start(seeded["ended"], _caller(), now=at(5))
    _set(seeded["ended"], state="ended", ended_at=at(4))
    seeded["error"] = _register(at(4), user_id=test_user.id)
    runs.start(seeded["error"], _caller(test_user.id), now=at(4))
    runs.executed(seeded["error"], _caller(test_user.id), 1, "the atomic failed", now=at(4))
    seeded["reviewed_changed"] = _register(at(3))
    _set(seeded["reviewed_changed"], state="reviewed", owner_id=test_user.id, reviewer_id=test_user.id,
         reviewed_at=at(1), changed_since_review=True)
    seeded["reviewed"] = _register(at(2))
    _set(seeded["reviewed"], state="reviewed", reviewer_id=test_user.id, reviewed_at=at(1))
    seeded["closed"] = _register(at(1))
    _set(seeded["closed"], state="closed", closed_at=at(0.5), close_reason="start timeout")
    return seeded


async def _pages(client: AsyncClient, path: str, limit: int, **params) -> list[dict]:
    rows, cursor = [], None
    for _ in range(50):
        response = await client.get(path, params={**params, "limit": limit, **({"cursor": cursor} if cursor else {})})
        assert response.status_code == 200, response.text
        body = response.json()
        rows.extend(body["data"])
        cursor = body["next_cursor"]
        if cursor is None:
            return rows
    raise AssertionError("pagination did not terminate")


async def _ids(client: AsyncClient, *filters: str) -> list[str]:
    response = await client.get("/svs/runs/", params={"f": list(filters)})
    assert response.status_code == 200, response.text
    return [row["run_id"] for row in response.json()["data"]]


NEWEST_FIRST = ["closed", "reviewed", "reviewed_changed", "error", "ended", "started", "created"]


class TestListing:
    @pytest.mark.asyncio
    async def test_newest_first_in_pages(self, client: AsyncClient, seeded):
        rows = await _pages(client, "/svs/runs/", limit=2)
        assert [row["run_id"] for row in rows] == [seeded[name] for name in NEWEST_FIRST]

    @pytest.mark.asyncio
    async def test_a_row(self, client: AsyncClient, seeded):
        (row,) = (await client.get("/svs/runs/", params={"f": "state:error"})).json()["data"]
        assert row["run_id"] == seeded["error"]
        assert (row["test_guid"], row["test_name"], row["technique"]) == (GUID, "PowerShell download", "T1059.001")
        assert row["targets"] == [{"hostname": "win10-01.lab.example", "username": "LAB\\svc_art",
                                   "host": "win10-01", "fqdn": "win10-01.lab.example", "user": "svc_art"}]
        assert (row["launcher"], row["batch_id"], row["exit_code"]) == ("art", "nightly", 1)
        assert row["error_reason"] and row["needs_attention"] is True
        assert row["marker"].startswith("svs-")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filters, expected", [
        (["needs_attention:true"], ["reviewed_changed", "error", "ended"]),
        (["needs_attention:false"], ["closed", "reviewed", "started", "created"]),
        (["state:started,created"], ["started", "created"]),
        (["!state:reviewed,closed"], ["error", "ended", "started", "created"]),
        ([f"test:{LINUX_GUID.upper()}"], ["started"]),
        (["test_name:credentials"], ["started"]),
        # a technique also finds its sub-techniques
        (["technique:T1059"], ["closed", "reviewed", "reviewed_changed", "error", "ended", "created"]),
        (["technique:T1003"], ["started"]),
        # a target matches by its short name or its fully qualified one
        (["target:LNX-01.lab.example"], ["started"]),
        (["!target:win10-01"], ["started"]),
        (["launcher:caldera"], ["started"]),
        (["batch:nightly"], ["closed", "reviewed", "reviewed_changed", "error", "ended", "created"]),
        # an inverted filter keeps the runs with no batch
        (["!batch:nightly"], ["started"]),
        (["created:-24h"], ["closed", "reviewed", "reviewed_changed", "error", "ended", "started"]),
        (["started:-24h"], ["error", "ended", "started"]),
        (["ended:-24h"], ["ended"]),
        (["owner:unittest"], ["reviewed_changed"]),
        # an inverted owner keeps the runs nobody owns
        (["!owner:unittest"], ["closed", "reviewed", "error", "ended", "started", "created"]),
        (["reviewer:unittest"], ["reviewed", "reviewed_changed"]),
        (["reason:start timeout"], ["closed"]),
        (["reason:atomic failed"], ["error"]),
        (["changed_since_review:true"], ["reviewed_changed"]),
        # filters are ANDed, the values of one ORed
        (["state:ended,error", "technique:T1059.001"], ["error", "ended"]),
    ])
    async def test_filters(self, client: AsyncClient, seeded, filters, expected):
        assert await _ids(client, *filters) == [seeded[name] for name in expected]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("f", ["state:bogus", "technique:1059", "test:not-a-guid", "needs_attention:maybe",
                                   "created:yesterday", "nope:1"])
    async def test_a_bad_filter_is_422(self, client: AsyncClient, f):
        assert (await client.get("/svs/runs/", params={"f": f})).status_code == 422

    @pytest.mark.asyncio
    async def test_a_bad_cursor_is_400(self, client: AsyncClient, seeded, no_settle):
        assert (await client.get("/svs/runs/", params={"cursor": "junk"})).status_code == 400

        # a cursor belongs to its order: changed_since pages by updated_at
        cursor = (await client.get("/svs/runs/", params={"limit": 1})).json()["next_cursor"]
        response = await client.get("/svs/runs/", params={"cursor": cursor, "changed_since": "2000-01-01T00:00:00"})
        assert response.status_code == 400


class TestChangedSince:
    @pytest.mark.asyncio
    async def test_a_changed_run_comes_back(self, client: AsyncClient, seeded, no_settle):
        rows = await _pages(client, "/svs/runs/", limit=3, changed_since="2000-01-01T00:00:00")
        assert sorted(row["run_id"] for row in rows) == sorted(seeded.values())
        keys = [(row["updated_at"], row["run_id"]) for row in rows]
        assert [key[0] for key in keys] == sorted(key[0] for key in keys)

        since, last = rows[-1]["updated_at"], rows[-1]["run_id"]
        runs.start(seeded["created"], _caller())
        rows = (await client.get("/svs/runs/", params={"changed_since": since})).json()["data"]
        # at least once: the last row of the earlier pull may come again
        assert seeded["created"] in [row["run_id"] for row in rows]
        assert {row["run_id"] for row in rows} <= {seeded["created"], last}

    @pytest.mark.asyncio
    async def test_an_unsettled_run_waits(self, client: AsyncClient, seeded, monkeypatch):
        monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 3600)
        response = await client.get("/svs/runs/", params={"changed_since": "2000-01-01T00:00:00"})
        assert response.json()["data"] == []
        # the default listing is not a change feed and does not wait
        assert len((await client.get("/svs/runs/")).json()["data"]) == len(seeded)

    @pytest.mark.asyncio
    async def test_the_future_is_empty(self, client: AsyncClient, seeded, no_settle):
        response = await client.get("/svs/runs/", params={"changed_since": "2999-01-01T00:00:00Z"})
        assert response.json() == {"data": [], "next_cursor": None}


class TestDetail:
    @pytest.mark.asyncio
    async def test_detail(self, client: AsyncClient, seeded):
        response = await client.get(f"/svs/runs/{seeded['error'].upper()}")
        assert response.status_code == 200, response.text
        run = response.json()
        assert run["run_id"] == seeded["error"] and run["state"] == "error"
        assert run["extra"] == {"ticket": 42}
        assert run["registered_by"] == "unittest" and run["launcher_error"] == "the atomic failed"
        assert run["observation_seconds"] == 3600 and len(run["test_content_hash"]) == 64

        reviewed = (await client.get(f"/svs/runs/{seeded['reviewed_changed']}")).json()
        assert (reviewed["owner"], reviewed["reviewer"], reviewed["changed_since_review"]) == ("unittest", "unittest", True)

    @pytest.mark.asyncio
    async def test_missing(self, client: AsyncClient):
        assert (await client.get("/svs/runs/not-a-uuid")).status_code == 400
        assert (await client.get(f"/svs/runs/{UNKNOWN_RUN}")).status_code == 404
        assert (await client.get("/svs/runs/not-a-uuid/events")).status_code == 400
        assert (await client.get(f"/svs/runs/{UNKNOWN_RUN}/events")).status_code == 404
        assert (await client.get(f"/svs/runs/{UNKNOWN_RUN}/events/export/ndjson")).status_code == 404


class TestEvents:
    @pytest.mark.asyncio
    async def test_a_runs_log(self, client: AsyncClient, seeded, test_user):
        events = await _pages(client, f"/svs/runs/{seeded['error']}/events", limit=2)
        assert [(e["kind"], e["from_state"], e["to_state"]) for e in events] == [
            ("registered", None, "created"),
            ("transition", "created", "started"),
            ("launcher_call", None, None),
            ("transition", "started", "error"),
            ("launcher_call", None, None),
        ]
        assert {e["run_id"] for e in events} == {seeded["error"]}
        assert [e["id"] for e in events] == sorted(e["id"] for e in events)
        registered, _, start_call, to_error, executed_call = events
        assert registered["details"]["extra"] == {"ticket": 42}
        assert (registered["actor"], registered["actor_user"]) == ("art-launcher", "unittest")
        assert start_call["details"] == {"call": "start", "outcome": "started", "payload": {}}
        assert executed_call["details"]["payload"] == {"error": "the atomic failed", "exit_code": 1}
        assert to_error["details"]["reason"]

    @pytest.mark.asyncio
    async def test_the_feed(self, client: AsyncClient, seeded, no_settle):
        events = await _pages(client, "/svs/runs/events", limit=4)
        assert {e["run_id"] for e in events} == set(seeded.values())
        keys = [(e["updated_at"], e["id"]) for e in events]
        assert keys == sorted(keys) and len(set(keys)) == len(keys)

        # the runs screen's filters pick the runs
        events = await _pages(client, "/svs/runs/events", limit=4, f="state:error")
        assert {e["run_id"] for e in events} == {seeded["error"]} and len(events) == 5

        since = max(e["updated_at"] for e in events)
        runs.cancel(seeded["started"], _caller())
        events = (await client.get("/svs/runs/events", params={"changed_since": since})).json()["data"]
        assert [(e["run_id"], e["to_state"]) for e in events if e["kind"] == "transition"] == [
            (seeded["started"], "canceled")]

    @pytest.mark.asyncio
    async def test_unsettled_events_wait(self, client: AsyncClient, seeded, monkeypatch):
        monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 3600)
        assert (await client.get("/svs/runs/events")).json()["data"] == []


class TestExport:
    @pytest.mark.asyncio
    async def test_runs(self, client: AsyncClient, seeded):
        lines = (await client.get("/svs/runs/export/ndjson", params={"f": "needs_attention:true"})).text.splitlines()
        assert [json.loads(line)["run_id"] for line in lines] == [seeded[n] for n in ("reviewed_changed", "error", "ended")]

        response = await client.get("/svs/runs/export/csv")
        assert response.headers["content-type"].startswith("text/csv")
        records = list(csv.DictReader(io.StringIO(response.text)))
        assert [r["run_id"] for r in records] == [seeded[name] for name in NEWEST_FIRST]
        assert next(r for r in records if r["run_id"] == seeded["error"])["targets"] == "win10-01.lab.example/LAB\\svc_art"
        assert next(r for r in records if r["run_id"] == seeded["started"])["targets"] == "lnx-01"

    @pytest.mark.asyncio
    async def test_events(self, client: AsyncClient, seeded, no_settle):
        lines = (await client.get(f"/svs/runs/{seeded['error']}/events/export/ndjson")).text.splitlines()
        assert len(lines) == 5 and json.loads(lines[0])["kind"] == "registered"

        records = list(csv.DictReader(io.StringIO((await client.get(f"/svs/runs/{seeded['error']}/events/export/csv")).text)))
        assert json.loads(records[0]["details"])["extra"] == {"ticket": 42}

        lines = (await client.get("/svs/runs/events/export/ndjson", params={"f": "state:closed"})).text.splitlines()
        assert {json.loads(line)["run_id"] for line in lines} == {seeded["closed"]}
        records = list(csv.DictReader(io.StringIO((await client.get("/svs/runs/events/export/csv")).text)))
        assert {r["run_id"] for r in records} == set(seeded.values())

    @pytest.mark.asyncio
    async def test_a_bad_filter_fails_before_the_stream(self, client: AsyncClient):
        for path in ("/svs/runs/export/ndjson", "/svs/runs/export/csv", "/svs/runs/events/export/ndjson",
                     "/svs/runs/events/export/csv"):
            assert (await client.get(path, params={"f": "state:bogus"})).status_code == 422


READS = ["/svs/runs/", "/svs/runs/export/ndjson", "/svs/runs/export/csv", "/svs/runs/events",
         "/svs/runs/events/export/ndjson", "/svs/runs/events/export/csv"]


@pytest.mark.asyncio
async def test_reading_needs_run_read(_override_db_session, session: AsyncSession, test_user, seeded, noperm_client):
    run_paths = [f"/svs/runs/{seeded['started']}", f"/svs/runs/{seeded['started']}/events",
                 f"/svs/runs/{seeded['started']}/events/export/csv"]

    reader = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(reader) as client:
        for path in READS + run_paths:
            assert (await client.get(path)).status_code == 200, path

    launcher = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_register")])
    async with api_key_client(launcher) as client:
        for path in READS + run_paths:
            assert (await client.get(path)).status_code == 403, path

    for path in READS + run_paths:
        assert (await noperm_client.get(path)).status_code == 403, path
