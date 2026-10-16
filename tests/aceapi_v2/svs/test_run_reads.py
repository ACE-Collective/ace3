"""GET /api/v2/svs/runs, the runs, their event logs and the event feed (docs/SVS_API.md, *Runs*)."""

import csv
import io
import json
import uuid
from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.runs import service
from saq.database.model import SVSAttribution, SVSRun, SVSRunResult
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs import run_summary, runs, windows
from saq.svs.constants import RunEventKind
from saq.svs.hosts import build_spec, create_host
from saq.svs.refusals import Caller
from saq.svs.run_events import new_run_event
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
    monkeypatch.setattr(windows, "hunt_info", lambda: {})
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
        assert row["platform"] == "windows"
        assert row["error_reason"] and row["needs_attention"] is True
        assert row["marker"].startswith("svs-")

    @pytest.mark.asyncio
    async def test_a_rows_result_and_alerts(self, client: AsyncClient, seeded):
        run_id = get_db().execute(select(SVSRun.id).where(SVSRun.uuid == seeded["ended"])).scalar_one()
        with private_transaction() as session:
            for status in ("hit", "missing", "possibly_suppressed", "candidate"):
                session.add(SVSRunResult(run_id=run_id, signature_uuid=str(uuid.uuid4()), status=status))
            session.add(SVSAttribution(run_id=run_id, alert_uuid=str(uuid.uuid4()), content_hash="1" * 64,
                                       signature_uuid=str(uuid.uuid4()), confidence="context", late=True,
                                       source="router", actor="svs", created_at=datetime.now()))

        (row,) = (await client.get("/svs/runs/", params={"f": "state:ended"})).json()["data"]
        assert (row["result_hit"], row["result_expected"], row["result_missing"], row["result_possibly_suppressed"],
                row["result_candidate"], row["result_stale"]) == (1, 3, 2, 1, 1, False)
        assert (row["alerts"], row["marker_alerts"], row["context_alerts"], row["late_alerts"]) == (1, 0, 1, 1)
        detail = (await client.get(f"/svs/runs/{seeded['ended']}")).json()
        assert (detail["result_hit"], detail["alerts"]) == (1, 1)
        assert (await client.get("/svs/runs/", params={"f": "has_missing:true"})).json()["data"][0]["run_id"] == \
            seeded["ended"]

    @pytest.mark.asyncio
    async def test_a_rows_signed_off_result(self, client: AsyncClient, seeded):
        """The result as signed off, beside the live one; only expected signatures count."""
        run_id = get_db().execute(select(SVSRun.id).where(SVSRun.uuid == seeded["reviewed"])).scalar_one()
        with private_transaction() as session:
            for status, reviewed in (("hit", "hit"), ("hit", "missing"), (None, "possibly_suppressed"),
                                     ("candidate", "candidate"), ("rejected", None)):
                session.add(SVSRunResult(run_id=run_id, signature_uuid=str(uuid.uuid4()), status=status,
                                         reviewed_status=reviewed))

        (row,) = (await client.get("/svs/runs/", params={"f": ["state:reviewed", "changed_since_review:false"]})).json()["data"]
        assert (row["result_hit"], row["result_expected"], row["result_candidate"]) == (2, 2, 1)
        assert (row["reviewed_hit"], row["reviewed_expected"], row["reviewed_missing"],
                row["reviewed_possibly_suppressed"]) == (1, 3, 2, 1)

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
        (["platform:Linux"], ["started"]),
        (["!platform:windows"], ["started"]),
        (["platform:macos"], []),
        (["launcher:caldera"], ["started"]),
        (["batch:nightly"], ["closed", "reviewed", "reviewed_changed", "error", "ended", "created"]),
        # an inverted filter keeps the runs with no batch
        (["!batch:nightly"], ["started"]),
        (["created:-24h"], ["closed", "reviewed", "reviewed_changed", "error", "ended", "started"]),
        (["started:-24h"], ["error", "ended", "started"]),
        (["ended:-24h"], ["ended"]),
        (["reviewed:-24h"], ["reviewed", "reviewed_changed"]),
        (["!reviewed:-24h"], ["closed", "error", "ended", "started", "created"]),
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
                                   "created:yesterday", "reviewed:yesterday", "nope:1"])
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
        assert next(r for r in records if r["run_id"] == seeded["started"])["platform"] == "linux"

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


class TestCount:
    @pytest.mark.asyncio
    async def test_count(self, client: AsyncClient, seeded):
        assert (await client.get("/svs/runs/count")).json() == {"count": len(seeded)}
        response = await client.get("/svs/runs/count", params={"f": "needs_attention:true"})
        assert response.status_code == 200, response.text
        assert response.json()["count"] == len(await _ids(client, "needs_attention:true")) == 3
        assert (await client.get("/svs/runs/count", params={"f": ["batch:nightly", "!state:closed"]})).json() == \
            {"count": 5}

    @pytest.mark.asyncio
    async def test_a_bad_filter(self, client: AsyncClient):
        assert (await client.get("/svs/runs/count", params={"f": "state:bogus"})).status_code == 422
        assert (await client.get("/svs/runs/count", params={"f": "nope:1"})).status_code == 422


class TestSuppressionShare:
    """GET /svs/runs/suppression-share: the ART-8 revisit trigger, over the signed-off results."""

    @staticmethod
    def _sign_off(run_uuid: str, *reviewed: str, at: datetime) -> None:
        run_id = get_db().execute(select(SVSRun.id).where(SVSRun.uuid == run_uuid)).scalar_one()
        with private_transaction() as session:
            for status in reviewed:
                session.add(SVSRunResult(run_id=run_id, signature_uuid=str(uuid.uuid4()), reviewed_status=status))
            session.add(new_run_event(run_id, RunEventKind.REVIEWED, "unittest", now=at))

    @pytest.mark.asyncio
    async def test_nothing_reviewed(self, client: AsyncClient):
        assert (await client.get("/svs/runs/suppression-share")).json() == {
            "missing": 0, "possibly_suppressed": 0, "share": None, "reviewed_runs": 0, "first_reviewed_at": None,
            "trigger_reached": False, "reconsider": False}

    @pytest.mark.asyncio
    async def test_the_share(self, client: AsyncClient, seeded):
        first = datetime.now() - timedelta(days=10)
        self._sign_off(seeded["reviewed"], "hit", "missing", "missing", "possibly_suppressed", at=first)
        # live statuses and other signed-off ones don't count
        self._sign_off(seeded["reviewed_changed"], "missing", "candidate", "rejected", at=first + timedelta(days=1))

        share = (await client.get("/svs/runs/suppression-share")).json()
        assert (share["missing"], share["possibly_suppressed"], share["share"], share["reviewed_runs"]) == (4, 1, 0.25, 2)
        assert datetime.fromisoformat(share["first_reviewed_at"]) == first
        # 2 runs in 10 days: not yet time to look
        assert (share["trigger_reached"], share["reconsider"]) == (False, False)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("days, runs_needed, reconsider", [
        (91, 50, True),     # 3 months since the first review
        (10, 2, True),      # enough reviewed runs
    ])
    async def test_the_trigger(self, client: AsyncClient, seeded, monkeypatch, days, runs_needed, reconsider):
        monkeypatch.setattr(run_summary, "SUPPRESSION_REVIEW_RUNS", runs_needed)
        self._sign_off(seeded["reviewed"], "missing", "possibly_suppressed", at=datetime.now() - timedelta(days=days))
        share = (await client.get("/svs/runs/suppression-share")).json()
        assert (share["trigger_reached"], share["reconsider"]) == (True, reconsider)

    @pytest.mark.asyncio
    async def test_at_most_the_threshold_is_not_worth_reconsidering(self, client: AsyncClient, seeded, monkeypatch):
        monkeypatch.setattr(run_summary, "SUPPRESSION_REVIEW_RUNS", 1)
        self._sign_off(seeded["reviewed"], *["missing"] * 9, "possibly_suppressed", at=datetime.now())
        share = (await client.get("/svs/runs/suppression-share")).json()
        assert (share["share"], share["trigger_reached"], share["reconsider"]) == (0.1, True, False)


def _add_results(run_uuid: str, *statuses: str) -> None:
    run_id = get_db().execute(select(SVSRun.id).where(SVSRun.uuid == run_uuid)).scalar_one()
    with private_transaction() as session:
        for status in statuses:
            session.add(SVSRunResult(run_id=run_id, signature_uuid=str(uuid.uuid4()), status=status))


class TestBatches:
    @pytest.mark.asyncio
    async def test_a_batch(self, client: AsyncClient, seeded):
        _add_results(seeded["ended"], "hit", "missing", "possibly_suppressed", "candidate")
        _add_results(seeded["reviewed"], "hit", "ignored")
        # the started run has no batch, so its result counts nowhere
        _add_results(seeded["started"], "hit")

        response = await client.get("/svs/runs/batches")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["next_cursor"] is None
        (batch,) = body["data"]
        assert (batch["batch_id"], batch["runs"], batch["needs_attention"]) == ("nightly", 6, 3)
        assert batch["states"] == {"created": 1, "started": 0, "ended": 1, "reviewed": 2, "canceled": 0, "error": 1,
                                   "closed": 1}
        created = {row["run_id"]: row["created_at"] for row in (await client.get("/svs/runs/")).json()["data"]}
        assert (batch["first_created_at"], batch["last_created_at"]) == (created[seeded["created"]],
                                                                         created[seeded["closed"]])
        assert (batch["result_hit"], batch["result_expected"], batch["result_missing"], batch["result_candidate"]) == \
            (2, 4, 2, 1)

        # the trailing slash the GUI's list pages request
        assert (await client.get("/svs/runs/batches/")).json() == body

    @pytest.mark.asyncio
    async def test_the_filters_pick_the_runs_counted(self, client: AsyncClient, seeded):
        _add_results(seeded["ended"], "hit", "missing")
        _add_results(seeded["reviewed"], "hit")
        (batch,) = (await client.get("/svs/runs/batches", params={"f": "state:reviewed"})).json()["data"]
        assert (batch["runs"], batch["states"]["reviewed"], batch["states"]["ended"]) == (2, 2, 0)
        assert (batch["result_hit"], batch["result_expected"], batch["result_missing"]) == (1, 1, 0)
        assert (await client.get("/svs/runs/batches", params={"f": "state:started"})).json()["data"] == []

    @pytest.mark.asyncio
    async def test_paging(self, client: AsyncClient, seeded):
        tie = datetime.now() + timedelta(hours=1)
        _register(tie, batch_id="tie-a")
        _register(tie, batch_id="tie-b")
        _register(tie - timedelta(hours=1, minutes=30), batch_id="older")
        _register(tie + timedelta(hours=1), batch_id="newest")
        rows = await _pages(client, "/svs/runs/batches", limit=1)
        # the batch with the latest run first; a tie goes by batch id, last first
        assert [row["batch_id"] for row in rows] == ["newest", "tie-b", "tie-a", "older", "nightly"]
        assert [row["batch_id"] for row in await _pages(client, "/svs/runs/batches", limit=2)] == \
            [row["batch_id"] for row in rows]

    @pytest.mark.asyncio
    async def test_bad_cursors(self, client: AsyncClient, seeded):
        _register(datetime.now(), batch_id="second")
        assert (await client.get("/svs/runs/batches", params={"cursor": "junk"})).status_code == 400
        runs_cursor = (await client.get("/svs/runs/", params={"limit": 1})).json()["next_cursor"]
        response = await client.get("/svs/runs/batches", params={"cursor": runs_cursor})
        assert response.status_code == 400 and "not by batch" in response.json()["detail"]
        assert (await client.get("/svs/runs/batches", params={"f": "state:bogus"})).status_code == 422

    @pytest.mark.asyncio
    async def test_exports(self, client: AsyncClient, seeded):
        _register(datetime.now(), batch_id="second")
        lines = (await client.get("/svs/runs/batches/export/ndjson")).text.splitlines()
        assert [json.loads(line)["batch_id"] for line in lines] == ["second", "nightly"]

        response = await client.get("/svs/runs/batches/export/csv", params={"f": "batch:nightly"})
        assert response.headers["content-type"].startswith("text/csv")
        (record,) = list(csv.DictReader(io.StringIO(response.text)))
        assert (record["batch_id"], record["runs"], record["state_reviewed"], record["state_started"]) == \
            ("nightly", "6", "2", "0")
        assert "states" not in record

        for path in ("/svs/runs/batches/export/ndjson", "/svs/runs/batches/export/csv"):
            assert (await client.get(path, params={"f": "state:bogus"})).status_code == 422


READS = ["/svs/runs/", "/svs/runs/export/ndjson", "/svs/runs/export/csv", "/svs/runs/suppression-share", "/svs/runs/events",
         "/svs/runs/events/export/ndjson", "/svs/runs/events/export/csv", "/svs/runs/count", "/svs/runs/batches",
         "/svs/runs/batches/export/ndjson", "/svs/runs/batches/export/csv"]


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
