"""GET /api/v2/svs/coverage, ATT&CK coverage and its daily snapshots (docs/SVS_API.md, *Coverage* and
*Coverage history*)."""

import csv
import io
import json
from datetime import date, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.coverage import service
from saq.database.model import SVSCoverage, SVSCoverageSnapshot, SVSCoverageState, SVSRun, SVSRunResult
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs import coverage, expectations
from saq.svs.attack import load_attack_catalog
from saq.svs.coverage import refresh_coverage
from saq.svs.signatures import SignatureTagsUnavailable
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.svs.conftest import (
    ATTACK_EXTRACT,
    add_catalog_test,
    add_test_host,
    started_run,
    write_hunt,
    write_yara_rule,
)

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
OTHER_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
REMOVED_GUID = "cccccccc-3333-4333-8333-333333333333"
SIGNATURE = "22222222-bbbb-4bbb-8bbb-222222222222"
HUNT = "44444444-dddd-4ddd-8ddd-444444444444"
DISABLED = "55555555-eeee-4eee-8eee-555555555555"
T0 = datetime(2026, 1, 16, 12, 0, 0)


@pytest.fixture
def attack_catalog(tmp_path, monkeypatch):
    """The miniature ATT&CK release, wherever coverage reads one."""
    path = tmp_path / "v99.0.json"
    path.write_text(json.dumps(ATTACK_EXTRACT))
    catalog = load_attack_catalog(path)
    for target in ("aceapi_v2.svs.coverage.service.get_attack_catalog", "saq.gui.filter_entry.get_attack_catalog",
                   "saq.svs.coverage.get_attack_catalog"):
        monkeypatch.setattr(target, lambda: catalog)
    return catalog


@pytest.fixture
def no_settle(monkeypatch):
    monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 0)


def _row(technique: str, platform: str, state: str = "none", **values) -> None:
    columns = dict(
        technique=technique, platform=platform, parent=technique.split(".")[0] if "." in technique else None,
        is_subtechnique="." in technique, technique_name=f"{technique} name", tactics=json.dumps(["TA0002"]),
        catalog_status="active", attack_platform=True, state=state, own_state=state, state_changed_at=T0,
        first_seen_at=T0)
    columns.update(values)
    with private_transaction() as session:
        session.add(SVSCoverage(**columns))


@pytest.fixture
def rows(attack_catalog):
    _row("T1059", "windows", "validated", own_state="none", tests_total=1, tests_validated=1)
    _row("T1059", "linux", "untested", attack_platform=False, tests_total=1)
    _row("T1059", "iaas", "none")
    _row("T1059.001", "windows", "validated", tests_total=1, tests_validated=1)
    _row("T1547", "windows", "manual", tactics=json.dumps(["TA0003", "TA0002"]), manual_signatures=1,
         technique_name="Boot or Logon Autostart Execution", state_changed_at=datetime.now() - timedelta(hours=1))
    _row("T1099", "windows", "none", catalog_status="deprecated", tactics="[]")
    _row("T1234", "windows", "untested", retired_at=T0, catalog_status="unknown")


async def _keys(client: AsyncClient, *filters: str, path: str = "/svs/coverage/") -> list[str]:
    response = await client.get(path, params={"f": list(filters)})
    assert response.status_code == 200, response.text
    return [f"{row['technique']}/{row['platform']}" for row in response.json()["data"]]


ORDER = ["T1059/iaas", "T1059/linux", "T1059/windows", "T1059.001/windows", "T1099/windows", "T1234/windows",
         "T1547/windows"]


class TestList:
    @pytest.mark.asyncio
    async def test_ordered_by_technique_then_platform(self, client: AsyncClient, rows):
        assert await _keys(client) == ORDER
        row = (await client.get("/svs/coverage/", params={"f": "technique:T1547"})).json()["data"][0]
        assert (row["tactics"], row["state"], row["manual_signatures"], row["retired_at"]) == (
            ["TA0003", "TA0002"], "manual", 1, None)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filters, expected", [
        # a technique also finds its sub-techniques
        (["technique:T1059"], ["T1059/iaas", "T1059/linux", "T1059/windows", "T1059.001/windows"]),
        (["technique:t1059.001"], ["T1059.001/windows"]),
        (["!technique:T1059"], ["T1099/windows", "T1234/windows", "T1547/windows"]),
        (["name:autostart"], ["T1547/windows"]),
        # an id or a shortname
        (["tactic:persistence"], ["T1547/windows"]),
        (["tactic:TA0003"], ["T1547/windows"]),
        # Atomic Red Team's names find the platform they count as
        (["platform:iaas:aws"], ["T1059/iaas"]),
        (["platform:linux,iaas"], ["T1059/iaas", "T1059/linux"]),
        (["state:validated,manual"], ["T1059/windows", "T1059.001/windows", "T1547/windows"]),
        (["own_state:none", "platform:windows"], ["T1059/windows", "T1099/windows"]),
        (["level:sub-technique"], ["T1059.001/windows"]),
        (["attack_platform:false"], ["T1059/linux"]),
        (["catalog_status:deprecated,unknown"], ["T1099/windows", "T1234/windows"]),
        (["has_manual:true"], ["T1547/windows"]),
        (["state_changed:-1d"], ["T1547/windows"]),
        (["retired:true"], ["T1234/windows"]),
        (["retired:false", "state:untested"], ["T1059/linux"]),
    ])
    async def test_filters(self, client: AsyncClient, rows, filters, expected):
        assert await _keys(client, *filters) == expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["technique:mimikatz", "tactic:nonsense", "state:great", "level:tactic",
                                       "nonsense:x"])
    async def test_a_bad_filter_is_422(self, client: AsyncClient, rows, value):
        assert (await client.get("/svs/coverage/", params={"f": value})).status_code == 422

    @pytest.mark.asyncio
    async def test_pages(self, client: AsyncClient, rows):
        keys, cursor = [], None
        while True:
            params = {"limit": 3} | ({"cursor": cursor} if cursor else {})
            page = (await client.get("/svs/coverage/", params=params)).json()
            keys += [f"{row['technique']}/{row['platform']}" for row in page["data"]]
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert keys == ORDER

    @pytest.mark.asyncio
    async def test_changed_since(self, client: AsyncClient, rows, no_settle):
        page = (await client.get("/svs/coverage/", params={"changed_since": "2000-01-01T00:00:00Z", "limit": 4})).json()
        rest = (await client.get("/svs/coverage/", params={"changed_since": "2000-01-01T00:00:00Z",
                                                           "cursor": page["next_cursor"]})).json()
        # in (updated_at, id) order: the order they were written
        assert [f"{row['technique']}/{row['platform']}" for row in page["data"] + rest["data"]] == [
            "T1059/windows", "T1059/linux", "T1059/iaas", "T1059.001/windows", "T1547/windows", "T1099/windows",
            "T1234/windows"]

        # a cursor of one order doesn't page the other
        response = await client.get("/svs/coverage/", params={"cursor": page["next_cursor"]})
        assert response.status_code == 400

        assert (await client.get("/svs/coverage/", params={"changed_since": "2999-01-01T00:00:00Z"})).json() == {
            "data": [], "next_cursor": None}

    @pytest.mark.asyncio
    async def test_unsettled_rows_wait(self, client: AsyncClient, rows, monkeypatch):
        monkeypatch.setattr(service, "CHANGED_SINCE_SETTLE_SECONDS", 3600)
        assert (await client.get("/svs/coverage/", params={"changed_since": "2000-01-01T00:00:00"})).json()["data"] == []

    @pytest.mark.asyncio
    async def test_exports(self, client: AsyncClient, rows):
        lines = (await client.get("/svs/coverage/export/ndjson", params={"f": "technique:T1059"})).text.splitlines()
        assert [json.loads(line)["platform"] for line in lines] == ["iaas", "linux", "windows", "windows"]

        response = await client.get("/svs/coverage/export/csv")
        assert response.headers["content-type"].startswith("text/csv")
        records = list(csv.DictReader(io.StringIO(response.text)))
        assert len(records) == len(ORDER)
        assert next(r for r in records if r["technique"] == "T1547")["tactics"] == "TA0003,TA0002"

    @pytest.mark.asyncio
    async def test_a_bad_filter_fails_before_the_stream(self, client: AsyncClient):
        for path in ("/svs/coverage/export/ndjson", "/svs/coverage/export/csv", "/svs/coverage/history/export/ndjson",
                     "/svs/coverage/history/export/csv"):
            assert (await client.get(path, params={"f": "state:great"})).status_code == 422


class TestSummary:
    @pytest.mark.asyncio
    async def test_counts(self, client: AsyncClient, rows):
        _refresh_state()
        summary = (await client.get("/svs/coverage/summary", params={"f": "retired:false"})).json()
        assert summary["rows"] == 6
        assert summary["states"] == {"failing": 0, "stale": 0, "validated": 2, "manual": 1, "untested": 1, "none": 2}
        assert summary["own_states"]["none"] == 3
        # the release's platforms first, in its order, then any other
        assert [(p["platform"], p["rows"]) for p in summary["platforms"]] == [("windows", 4), ("iaas", 1),
                                                                             ("linux", 1)]
        assert summary["platforms"][0]["states"]["validated"] == 2
        assert (summary["attack_release"], summary["unknown_tags"], summary["error"]) == ("v99.0", 0, None)

        summary = (await client.get("/svs/coverage/summary", params={"f": "platform:linux"})).json()
        assert (summary["rows"], summary["states"]["untested"]) == (1, 1)

    @pytest.mark.asyncio
    async def test_before_any_refresh(self, client: AsyncClient, attack_catalog):
        summary = (await client.get("/svs/coverage/summary")).json()
        assert (summary["rows"], summary["refreshed_at"], summary["platforms"]) == (0, None, [])


def _refresh_state():
    # a state row as a refresh leaves it, without touching the rows
    with private_transaction() as session:
        session.add(SVSCoverageState(id=coverage.STATE_ID, attack_release="v99.0", refreshed_at=T0, duration_ms=5,
                                     rows=6))


#
# the drill-down
#

@pytest.fixture
def drill_down(attack_catalog, hunt_dir, yara_dir, test_user):
    """T1059 and its sub-techniques, refreshed: one validated PowerShell test on windows, one test of
    the parent never run on linux, a removed test, a counting tag and a disabled one."""
    write_hunt(hunt_dir, HUNT, name="powershell hunt", tags=["mitre:T1086"])
    write_yara_rule(yara_dir, "old_rule", DISABLED, mitre_attack="T1059", enabled="false")

    add_test_host("win10-01")
    add_catalog_test(GUID)
    add_catalog_test(OTHER_GUID, technique="T1059", platforms=("linux",), name="Bash")
    add_catalog_test(REMOVED_GUID, technique="T1059.002", platforms=("macos",), removed=True, name="AppleScript")

    expectations.set_expectation(GUID, SIGNATURE, "expected", test_user.id, platform="windows")
    run = started_run(GUID)
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(state="reviewed", reviewed_at=T0))
    db.commit()
    with private_transaction() as session:
        session.add(SVSRunResult(run_id=run.id, signature_uuid=SIGNATURE, status="hit", reviewed_status="hit"))

    refresh_coverage("test")
    return run.uuid


class TestTechnique:
    @pytest.mark.asyncio
    async def test_drill_down(self, client: AsyncClient, drill_down):
        response = await client.get("/svs/coverage/T1059")
        assert response.status_code == 200, response.text
        detail = response.json()
        assert (detail["requested"], detail["technique"], detail["name"], detail["catalog_status"],
                detail["attack_release"]) == ("T1059", "T1059", "Command and Scripting Interpreter", "active", "v99.0")
        assert detail["refreshed_at"] is not None
        assert {(row["platform"], row["state"], row["own_state"]) for row in detail["rows"]} == {
            ("windows", "validated", "none"), ("macos", "none", "none"), ("linux", "untested", "untested")}
        assert {(row["technique"], row["platform"]) for row in detail["sub_technique_rows"]} == {
            ("T1059.001", "windows"), ("T1059.002", "macos")}

        tests = {(test["guid"], test["platform"]): test for test in detail["tests"]}
        assert set(tests) == {(GUID, "windows"), (OTHER_GUID, "linux")}
        validated = tests[(GUID, "windows")]
        assert (validated["technique"], validated["test_state"], validated["contribution"],
                validated["last_reviewed_run_id"], validated["expected_signatures"]) == (
            "T1059.001", "validated", "validated", drill_down, [SIGNATURE])
        assert (tests[(OTHER_GUID, "linux")]["test_state"], tests[(OTHER_GUID, "linux")]["contribution"]) == (
            "never_run", "untested")

        assert detail["measured_signatures"] == [
            {"signature_uuid": SIGNATURE, "name": None, "family": None, "tests": [{"guid": GUID, "platform": "windows"}]}]
        # T1086 was revoked by T1059.001
        manual = {mapping["signature_uuid"]: mapping for mapping in detail["manual_signatures"]}
        assert (manual[HUNT]["declared"], manual[HUNT]["technique"], manual[HUNT]["counts"]) == (
            "T1086", "T1059.001", True)
        assert (manual[DISABLED]["counts"], manual[DISABLED]["reason"]) == (False, "not_counting")
        assert [test["guid"] for test in detail["removed_tests"]] == [REMOVED_GUID]

    @pytest.mark.asyncio
    async def test_a_sub_technique(self, client: AsyncClient, drill_down):
        detail = (await client.get("/svs/coverage/t1059.001")).json()
        assert (detail["technique"], detail["parent"], detail["is_subtechnique"]) == ("T1059.001", "T1059", True)
        assert [test["guid"] for test in detail["tests"]] == [GUID]
        assert detail["sub_technique_rows"] == []
        assert [mapping["signature_uuid"] for mapping in detail["manual_signatures"]] == [HUNT]

    @pytest.mark.asyncio
    async def test_a_revoked_id_answers_for_its_successor(self, client: AsyncClient, drill_down):
        detail = (await client.get("/svs/coverage/T1086")).json()
        assert (detail["requested"], detail["technique"]) == ("T1086", "T1059.001")

    @pytest.mark.asyncio
    async def test_unreadable_tags(self, client: AsyncClient, drill_down, monkeypatch):
        def unavailable():
            raise SignatureTagsUnavailable("unable to load yara signatures from rules: boom")

        monkeypatch.setattr(coverage, "signature_techniques", unavailable)
        detail = (await client.get("/svs/coverage/T1059")).json()
        assert (detail["manual_signatures"], detail["manual_signatures_error"]) == (
            [], "unable to load yara signatures from rules: boom")
        assert len(detail["tests"]) == 2

    @pytest.mark.asyncio
    async def test_errors(self, client: AsyncClient, attack_catalog):
        assert (await client.get("/svs/coverage/mimikatz")).status_code == 400
        assert (await client.get("/svs/coverage/T9999")).status_code == 404
        # a deprecated technique the release has answers with no rows
        assert (await client.get("/svs/coverage/T1099")).json()["catalog_status"] == "deprecated"


#
# the history
#

def _snapshot(day: date, technique: str, platform: str, state: str, own_state: str | None = None) -> None:
    with private_transaction() as session:
        session.add(SVSCoverageSnapshot(snapshot_date=day, technique=technique, platform=platform,
                                        attack_release="v99.0", parent=None, is_subtechnique="." in technique,
                                        state=state, own_state=own_state or state))


@pytest.fixture
def history(attack_catalog):
    _snapshot(date(2026, 9, 29), "T1059", "windows", "untested")
    _snapshot(date(2026, 9, 29), "T1547", "windows", "none")
    _snapshot(date(2026, 9, 30), "T1059", "windows", "validated", "none")
    _snapshot(date(2026, 9, 30), "T1547", "windows", "manual")
    _snapshot(date(2026, 10, 1), "T1059", "windows", "failing")
    _snapshot(date(2026, 10, 1), "T1059.001", "windows", "failing")
    _snapshot(date(2026, 10, 1), "T1547", "linux", "none")


class TestHistory:
    @pytest.mark.asyncio
    async def test_list(self, client: AsyncClient, history):
        page = (await client.get("/svs/coverage/history", params={"limit": 4})).json()
        rest = (await client.get("/svs/coverage/history", params={"cursor": page["next_cursor"]})).json()
        assert [(row["snapshot_date"], row["technique"], row["platform"]) for row in page["data"] + rest["data"]] == [
            ("2026-09-29", "T1059", "windows"), ("2026-09-29", "T1547", "windows"),
            ("2026-09-30", "T1059", "windows"), ("2026-09-30", "T1547", "windows"),
            ("2026-10-01", "T1059", "windows"), ("2026-10-01", "T1059.001", "windows"),
            ("2026-10-01", "T1547", "linux")]
        assert rest["next_cursor"] is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filters, expected", [
        (["date:09-30-2026 00:00 - 09-30-2026 23:59"], 2),
        (["technique:T1059"], 4),
        (["platform:linux"], 1),
        (["state:failing"], 2),
        (["own_state:none"], 3),
        (["level:sub-technique"], 1),
    ])
    async def test_filters(self, client: AsyncClient, history, filters, expected):
        response = await client.get("/svs/coverage/history", params={"f": filters})
        assert response.status_code == 200, response.text
        assert len(response.json()["data"]) == expected

    @pytest.mark.asyncio
    async def test_changed_since(self, client: AsyncClient, history, no_settle):
        page = (await client.get("/svs/coverage/history", params={"changed_since": "2000-01-01T00:00:00Z"})).json()
        assert len(page["data"]) == 7

    @pytest.mark.asyncio
    async def test_exports(self, client: AsyncClient, history):
        lines = (await client.get("/svs/coverage/history/export/ndjson", params={"f": "state:failing"})).text.splitlines()
        assert [json.loads(line)["technique"] for line in lines] == ["T1059", "T1059.001"]
        records = list(csv.DictReader(io.StringIO((await client.get("/svs/coverage/history/export/csv")).text)))
        assert (len(records), records[0]["snapshot_date"]) == (7, "2026-09-29")

    @pytest.mark.asyncio
    async def test_counts_per_day(self, client: AsyncClient, history):
        counts = (await client.get("/svs/coverage/history/counts", params={"f": "platform:windows"})).json()
        assert counts["group"] == "day"
        assert [(p["period"], p["rows"], p["states"]["failing"]) for p in counts["data"]] == [
            ("2026-09-29", 2, 0), ("2026-09-30", 2, 0), ("2026-10-01", 2, 2)]
        assert counts["data"][1]["own_states"] == {"failing": 0, "stale": 0, "validated": 0, "manual": 1,
                                                   "untested": 0, "none": 1}

    @pytest.mark.asyncio
    async def test_counts_per_month_take_the_last_snapshot(self, client: AsyncClient, history):
        counts = (await client.get("/svs/coverage/history/counts", params={"group": "month"})).json()
        assert [(p["period"], p["snapshot_date"], p["rows"]) for p in counts["data"]] == [
            ("2026-09", "2026-09-30", 2), ("2026-10", "2026-10-01", 3)]
        assert counts["data"][0]["states"]["validated"] == 1

        # a day the other filters leave empty is still its month's last
        counts = (await client.get("/svs/coverage/history/counts",
                                   params={"group": "month", "f": "state:untested"})).json()
        assert [(p["period"], p["snapshot_date"], p["rows"]) for p in counts["data"]] == [
            ("2026-09", "2026-09-30", 0), ("2026-10", "2026-10-01", 0)]

        counts = (await client.get("/svs/coverage/history/counts",
                                   params={"f": "date:10-01-2026 00:00 - 10-31-2026 23:59"})).json()
        assert [p["period"] for p in counts["data"]] == ["2026-10-01"]

    @pytest.mark.asyncio
    async def test_counts_errors(self, client: AsyncClient, attack_catalog):
        assert (await client.get("/svs/coverage/history/counts")).json() == {"group": "day", "data": []}
        assert (await client.get("/svs/coverage/history/counts", params={"group": "year"})).status_code == 422


@pytest.mark.asyncio
async def test_worked_example_coverage_over_time(client: AsyncClient, attack_catalog):
    """docs/SVS_API.md, *Technique coverage over time*, run against the API."""
    _snapshot(date(2026, 9, 30), "T1059", "windows", "untested")
    _snapshot(date(2026, 9, 30), "T1547", "windows", "manual")
    _snapshot(date(2026, 9, 30), "T1059.001", "windows", "validated")     # a sub-technique: left out
    _snapshot(date(2026, 9, 30), "T1059", "iaas", "validated")            # not an endpoint platform
    _snapshot(date(2026, 10, 15), "T1059", "windows", "validated")
    _snapshot(date(2026, 10, 15), "T1547", "windows", "failing")

    params = {"group": "month", "f": ["platform:windows,linux,macos", "level:technique"]}
    counts = (await client.get("/svs/coverage/history/counts", params=params)).json()
    report = []
    for period in counts["data"]:
        if period["rows"]:
            states = period["states"]
            report.append((period["period"], f"{states['validated'] / period['rows']:.0%} validated",
                           f"{states['failing'] / period['rows']:.0%} failing"))

    assert report == [("2026-09", "0% validated", "0% failing"), ("2026-10", "50% validated", "50% failing")]


@pytest.mark.asyncio
async def test_permissions(_override_db_session, session: AsyncSession, test_user, rows, noperm_client):
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "run_read")])
    async with api_key_client(key) as client:
        for path in ("/svs/coverage/", "/svs/coverage/summary", "/svs/coverage/history",
                     "/svs/coverage/history/counts", "/svs/coverage/T1059"):
            assert (await client.get(path)).status_code == 200, path
    for path in ("/svs/coverage/", "/svs/coverage/summary", "/svs/coverage/history", "/svs/coverage/T1059"):
        assert (await noperm_client.get(path)).status_code == 403, path
