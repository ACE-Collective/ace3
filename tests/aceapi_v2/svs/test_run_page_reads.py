"""What the run page reads besides the run's own rows (docs/SVS_API.md, *Run alerts* and *Run
history*): the review blockers and the log search link on GET /svs/runs/{run_id}, the run's alerts
(GET /svs/runs/{run_id}/alerts) and how its signatures did before (GET /svs/runs/{run_id}/history)."""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, update

from saq.alert_routing import reset_alert_routers
from saq.configuration.config import get_config
from saq.constants import F_HOSTNAME
from saq.database.model import Alert, SVSRun, SVSRunResult
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.database.util.alert import ALERT
from saq.svs import runs
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
OTHER_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
RULE = "22222222-bbbb-4bbb-8bbb-222222222222"
SIGNATURE_A = "33333333-cccc-4ccc-8ccc-333333333333"
SIGNATURE_B = "44444444-dddd-4ddd-8ddd-444444444444"


@pytest.fixture(autouse=True)
def setup(no_hunts, yara_dir):
    reset_alert_routers()
    add_catalog_test(GUID)
    add_catalog_test(OTHER_GUID)
    add_test_host("win10-01")
    yield
    reset_alert_routers()


def _alert(*, marker=None, host="win10-01", event_time=None, signature_uuid=None, description="hunt hit") -> str:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=event_time or datetime.now())
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    if marker:
        root.details = {"cmd": marker}
    root.add_detection_point(description, signature_uuid=signature_uuid)
    root.save()
    ALERT(root)
    return root.uuid


class TestDetail:
    @pytest.mark.asyncio
    async def test_a_started_run(self, client: AsyncClient):
        run = started_run(GUID)
        body = (await client.get(f"/svs/runs/{run.uuid}")).json()
        assert (body["review_blockers"], body["log_search_url"]) == (None, None)

    @pytest.mark.asyncio
    async def test_review_blockers(self, client: AsyncClient):
        run = started_run(GUID, now=datetime.now() - timedelta(hours=3))
        _alert(marker=run.marker, event_time=datetime.now() - timedelta(hours=2), signature_uuid=RULE)
        context = _alert(event_time=datetime.now() - timedelta(hours=2))
        runs.run_timers(now=run.observation_ends_at + timedelta(seconds=1))

        blockers = (await client.get(f"/svs/runs/{run.uuid}")).json()["review_blockers"]
        assert blockers == {"stale": False, "candidates": [RULE], "context_alerts": [context]}
        # what the run page shows is what a review answers
        detail = (await client.post(f"/svs/runs/{run.uuid}/review")).json()["detail"]
        assert (detail["candidates"], detail["context_alerts"]) == ([RULE], [context])

        await client.put(f"/svs/tests/{GUID}/expectations/windows/{RULE}", json={"state": "expected"})
        await client.post(f"/svs/runs/{run.uuid}/alerts/{context}/keep")
        blockers = (await client.get(f"/svs/runs/{run.uuid}")).json()["review_blockers"]
        # the result still names the candidate until the timers recompute it
        assert blockers == {"stale": True, "candidates": [RULE], "context_alerts": []}
        runs.run_timers()
        blockers = (await client.get(f"/svs/runs/{run.uuid}")).json()["review_blockers"]
        assert blockers == {"stale": False, "candidates": [], "context_alerts": []}

    @pytest.mark.asyncio
    async def test_the_log_search_url(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(get_config().svs, "log_search_url",
                            "https://logs.example/search?q=svs_run%3D{run_uuid}&m={marker}&t={test_guid}"
                            "&earliest={earliest}&latest={latest}")
        started = datetime.now() - timedelta(hours=30)
        run = started_run(GUID, now=started)
        body = (await client.get(f"/svs/runs/{run.uuid}")).json()

        # epoch seconds of the run's naive UTC times, as stored; its attribution window has passed, so it ends
        # the search
        def epoch(value: str) -> int:
            return int(datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp())

        assert body["log_search_url"] == (
            f"https://logs.example/search?q=svs_run%3D{run.uuid}&m={run.marker}&t={GUID}"
            f"&earliest={epoch(body['started_at'])}&latest={epoch(body['attribution_ends_at'])}")


class TestAlerts:
    @pytest.fixture
    def alerts(self, client: AsyncClient):
        run = started_run(GUID, now=datetime.now() - timedelta(minutes=5))
        return run, {
            "marked": _alert(marker=run.marker, description="marked hit"),
            "context": _alert(),
            "manual": _alert(host="srv-01"),
            "removed": _alert(host="srv-02"),
        }

    @pytest.mark.asyncio
    async def test_the_alerts(self, client: AsyncClient, alerts, test_user):
        run, uuids = alerts
        for name in ("manual", "removed"):
            response = await client.post(f"/svs/runs/{run.uuid}/alerts/{uuids[name]}/associate")
            assert response.status_code == 200, response.text
        await client.post(f"/svs/runs/{run.uuid}/alerts/{uuids['removed']}/disassociate", json={"reason": "wrong"})

        body = (await client.get(f"/svs/runs/{run.uuid}/alerts")).json()
        assert body["next_cursor"] is None
        rows = {row["alert_uuid"]: row for row in body["data"]}
        # in the order they were first attributed
        assert [row["alert_uuid"] for row in body["data"]] == list(uuids.values())

        marked = rows[uuids["marked"]]
        assert (marked["holds"], marked["confidence"], marked["late"], marked["manual"], marked["kept"],
                marked["undecided_context"]) == (True, "marker", False, False, False, False)
        assert (marked["alert"]["uuid"], marked["alert"]["svs_status"], marked["alert"]["svs_runs"]) == (
            uuids["marked"], "test", [run.uuid])
        (detection,) = marked["detections"]
        assert (detection["description"], detection["attribution"]["confidence"],
                detection["attribution"]["source"]) == ("marked hit", "marker", "router")

        context = rows[uuids["context"]]
        assert (context["confidence"], context["undecided_context"], context["alert"]["svs_status"]) == (
            "context", True, "test?")
        manual = rows[uuids["manual"]]
        assert (manual["confidence"], manual["manual"]) == ("marker", True)
        removed = rows[uuids["removed"]]
        assert (removed["holds"], removed["confidence"], removed["alert"]["svs_status"]) == (False, None, None)
        assert removed["detections"][0]["attribution"]["removal_reason"] == "wrong"

        await client.post(f"/svs/runs/{run.uuid}/alerts/{uuids['context']}/keep")
        rows = {row["alert_uuid"]: row for row in (await client.get(f"/svs/runs/{run.uuid}/alerts")).json()["data"]}
        assert (rows[uuids["context"]]["kept"], rows[uuids["context"]]["undecided_context"]) == (True, False)

    @pytest.mark.asyncio
    async def test_paging_and_export(self, client: AsyncClient, alerts):
        run, uuids = alerts
        first = (await client.get(f"/svs/runs/{run.uuid}/alerts", params={"limit": 1})).json()
        second = (await client.get(f"/svs/runs/{run.uuid}/alerts",
                                   params={"limit": 5, "cursor": first["next_cursor"]})).json()
        assert [row["alert_uuid"] for row in first["data"] + second["data"]] == [uuids["marked"], uuids["context"]]
        assert second["next_cursor"] is None
        assert (await client.get(f"/svs/runs/{run.uuid}/alerts", params={"cursor": "junk"})).status_code == 400

        lines = (await client.get(f"/svs/runs/{run.uuid}/alerts/export/ndjson")).text.splitlines()
        assert [json.loads(line)["alert_uuid"] for line in lines] == [uuids["marked"], uuids["context"]]

    @pytest.mark.asyncio
    async def test_an_alert_that_is_gone(self, client: AsyncClient, alerts):
        run, uuids = alerts
        db = get_db()
        db.execute(delete(Alert).where(Alert.uuid == uuids["marked"]))
        db.commit()

        row = (await client.get(f"/svs/runs/{run.uuid}/alerts")).json()["data"][0]
        assert (row["alert_uuid"], row["alert"], row["holds"]) == (uuids["marked"], None, True)
        (detection,) = row["detections"]
        assert (detection["description"], detection["attribution"]["confidence"]) == (None, "marker")

    @pytest.mark.asyncio
    async def test_unknown_runs(self, client: AsyncClient):
        assert (await client.get(f"/svs/runs/{uuid.uuid4()}/alerts")).status_code == 404
        assert (await client.get("/svs/runs/not-a-uuid/alerts")).status_code == 400


def _run_with_results(state: str, created: datetime, results: dict[str, tuple], guid: str = GUID,
                      host: str = "win10-01") -> str:
    """A run of the test in that state, with result rows: signature -> (status, reviewed_status)."""
    run = started_run(guid, host, now=created)
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(state=state))
    db.commit()
    with private_transaction() as session:
        for signature_uuid, (status, reviewed_status) in results.items():
            session.add(SVSRunResult(run_id=run.id, signature_uuid=signature_uuid, status=status,
                                     reviewed_status=reviewed_status))
    return run.uuid


class TestHistory:
    @pytest.mark.asyncio
    async def test_history(self, client: AsyncClient):
        now = datetime.now()
        reviewed = _run_with_results("reviewed", now - timedelta(days=4),
                                     {SIGNATURE_A: ("missing", "hit"), SIGNATURE_B: (None, "candidate")})
        ended = _run_with_results("ended", now - timedelta(days=3), {SIGNATURE_A: ("missing", None)})
        _run_with_results("closed", now - timedelta(days=2), {SIGNATURE_A: ("hit", None)})
        _run_with_results("ended", now - timedelta(days=2), {SIGNATURE_A: ("hit", None)}, guid=OTHER_GUID)
        run = _run_with_results("ended", now - timedelta(days=1),
                                {SIGNATURE_A: ("hit", None), SIGNATURE_B: ("candidate", None)})
        _run_with_results("ended", now, {SIGNATURE_A: ("hit", None)})

        body = (await client.get(f"/svs/runs/{run}/history")).json()
        assert [(row["run_id"], row["state"]) for row in body["runs"]] == [(ended, "ended"), (reviewed, "reviewed")]
        # a reviewed run's status as it was signed off, an ended run's live one
        assert body["signatures"] == [
            {"signature_uuid": SIGNATURE_A, "statuses": ["missing", "hit"]},
            {"signature_uuid": SIGNATURE_B, "statuses": [None, "candidate"]},
        ]

        body = (await client.get(f"/svs/runs/{run}/history", params={"runs": 1})).json()
        assert ([row["run_id"] for row in body["runs"]], body["signatures"][0]["statuses"]) == ([ended], ["missing"])

    @pytest.mark.asyncio
    async def test_only_runs_on_the_same_platform(self, client: AsyncClient):
        multi = "eeeeeeee-5555-4555-8555-555555555555"
        add_catalog_test(multi, platforms=("windows", "linux"))
        add_test_host("windows-01", platform="windows")
        add_test_host("linux-01", platform="linux")
        now = datetime.now()
        earlier = _run_with_results("ended", now - timedelta(days=3), {SIGNATURE_A: ("hit", None)}, multi, "linux-01")
        _run_with_results("ended", now - timedelta(days=2), {SIGNATURE_A: ("missing", None)}, multi, "windows-01")
        run = _run_with_results("ended", now - timedelta(days=1), {SIGNATURE_A: ("hit", None)}, multi, "linux-01")

        body = (await client.get(f"/svs/runs/{run}/history")).json()
        assert [row["run_id"] for row in body["runs"]] == [earlier]
        assert body["signatures"] == [{"signature_uuid": SIGNATURE_A, "statuses": ["hit"]}]

    @pytest.mark.asyncio
    async def test_a_first_run(self, client: AsyncClient):
        run = _run_with_results("ended", datetime.now(), {SIGNATURE_A: ("candidate", None)})
        body = (await client.get(f"/svs/runs/{run}/history")).json()
        assert body == {"runs": [], "signatures": [{"signature_uuid": SIGNATURE_A, "statuses": []}]}

    @pytest.mark.asyncio
    async def test_bad_requests(self, client: AsyncClient):
        run = started_run(GUID)
        for runs_param in (0, 51):
            assert (await client.get(f"/svs/runs/{run.uuid}/history", params={"runs": runs_param})).status_code == 422
        assert (await client.get(f"/svs/runs/{uuid.uuid4()}/history")).status_code == 404
        assert (await client.get("/svs/runs/not-a-uuid/history")).status_code == 400


@pytest.mark.asyncio
async def test_reading_needs_run_read(noperm_client: AsyncClient):
    run = started_run(GUID)
    for path in ("alerts", "alerts/export/ndjson", "history"):
        assert (await noperm_client.get(f"/svs/runs/{run.uuid}/{path}")).status_code == 403
