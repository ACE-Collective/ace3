"""ATT&CK coverage per technique and platform (saq.svs.coverage, docs/SVS_COVERAGE.md)."""

import json
from argparse import Namespace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select, update

from saq.cli.commands.svs import cli_coverage_refresh, cli_coverage_snapshot, cli_coverage_status
from saq.configuration.config import get_service_config
from saq.constants import ENV_ACE_IS_PRIMARY_NODE, SERVICE_YARA_SCANNER
from saq.database.model import (
    SVSCatalogTest,
    SVSCoverage,
    SVSCoverageSnapshot,
    SVSCoverageState,
    SVSRun,
    SVSRunResult,
    User,
)
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.signatures.locations import LOCATION_RESOLVERS
from saq.signatures.model import SignatureType
from saq.svs import coverage, expectations
from saq.svs.constants import CoverageState
from saq.svs.coverage import (
    STATE_ID,
    compute_rows,
    contribution_state,
    refresh_coverage,
    write_snapshot,
)
from saq.svs.service import CoverageRefresher, SVSService
from saq.svs.signatures import SignatureTags, SignatureTagsUnavailable, signature_techniques
from saq.svs.test_state import Evaluation, TestState
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run, write_hunt, write_yara_rule

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
OTHER_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
SIGNATURE = "22222222-bbbb-4bbb-8bbb-222222222222"
OTHER_SIGNATURE = "44444444-dddd-4ddd-8ddd-444444444444"
T0 = datetime(2026, 10, 16, 12, 0, 0)
DAY = date(2026, 10, 16)


def _test(guid: str = GUID, technique: str = "T1059.001", platforms=("windows",),
          technique_name: str = "From the test") -> SVSCatalogTest:
    return SVSCatalogTest(guid=guid, technique=technique, technique_name=technique_name,
                          platforms=json.dumps(list(platforms)))


def _evaluation(state: TestState, *, reviewed_at: datetime | None = T0, expected=(),
                unjudged: bool = False) -> Evaluation:
    run = SimpleNamespace(reviewed_at=reviewed_at) if reviewed_at is not None else None
    return Evaluation(state, run, frozenset(expected), unjudged)


def _tag(uuid: str, *declared: str, counts: bool = True, ignored=()) -> SignatureTags:
    return SignatureTags(uuid, "hunt", f"hunt {uuid[:4]}", counts, tuple(declared), tuple(ignored))


def _states(computed) -> dict[tuple[str, str], tuple[str, str]]:
    return {key: (row.state, row.own_state) for key, row in computed.rows.items()}


#
# compute_rows
#

@pytest.mark.unit
class TestComputeRows:
    def test_every_active_technique_has_its_platforms(self, attack_catalog):
        computed = compute_rows(attack_catalog, [], {}, {})
        # T1099 is deprecated and nothing names it
        assert sorted(computed.rows) == [("T1059", "macos"), ("T1059", "windows"), ("T1059.001", "windows"),
                                         ("T1059.002", "macos"), ("T1547", "windows")]
        row = computed.rows[("T1059.001", "windows")]
        assert (row.state, row.own_state, row.parent, row.is_subtechnique, row.technique_name, row.catalog_status,
                row.attack_platform, json.loads(row.tactics)) == (
            "none", "none", "T1059", True, "PowerShell", "active", True, ["TA0002"])
        assert computed.rows[("T1547", "windows")].tactics == json.dumps(["TA0003", "TA0002"])

    @pytest.mark.parametrize("evaluation,expected", [
        (None, CoverageState.UNTESTED),
        (_evaluation(TestState.VALIDATED), CoverageState.VALIDATED),
        (_evaluation(TestState.FAILING), CoverageState.FAILING),
        (_evaluation(TestState.STALE), CoverageState.STALE),
        (_evaluation(TestState.NO_EXPECTATIONS), CoverageState.UNTESTED),
        # nothing reviewed yet
        (_evaluation(TestState.AWAITING_REVIEW, reviewed_at=None, expected=[SIGNATURE], unjudged=True),
         CoverageState.UNTESTED),
        # expected only after its latest review
        (_evaluation(TestState.AWAITING_REVIEW, expected=[SIGNATURE], unjudged=True), CoverageState.STALE),
    ])
    def test_contribution_state(self, evaluation, expected):
        assert contribution_state(evaluation) == expected

    def test_worst_first(self, attack_catalog):
        tests = [_test(GUID), _test(OTHER_GUID)]
        evaluations = {(GUID, "windows"): _evaluation(TestState.VALIDATED),
                       (OTHER_GUID, "windows"): _evaluation(TestState.FAILING)}
        row = compute_rows(attack_catalog, tests, evaluations, {}).rows[("T1059.001", "windows")]
        assert (row.state, row.tests_total, row.tests_validated, row.tests_failing, row.tests_stale) == (
            "failing", 2, 1, 1, 0)

    def test_untested_is_below_manual(self, attack_catalog):
        computed = compute_rows(attack_catalog, [_test()], {}, {SIGNATURE: _tag(SIGNATURE, "T1059.001")})
        assert _states(computed)[("T1059.001", "windows")] == ("manual", "manual")
        computed = compute_rows(attack_catalog, [_test()], {(GUID, "windows"): _evaluation(TestState.STALE)},
                                {SIGNATURE: _tag(SIGNATURE, "T1059.001")})
        assert _states(computed)[("T1059.001", "windows")] == ("stale", "stale")

    def test_sub_techniques_roll_up_on_their_platform(self, attack_catalog):
        computed = compute_rows(attack_catalog, [_test()], {(GUID, "windows"): _evaluation(TestState.VALIDATED)}, {})
        states = _states(computed)
        assert states[("T1059.001", "windows")] == ("validated", "validated")
        assert states[("T1059", "windows")] == ("validated", "none")
        assert states[("T1059", "macos")] == ("none", "none")
        assert computed.rows[("T1059", "windows")].tests_validated == 1

    def test_a_test_platform_attack_does_not_list_gets_rows(self, attack_catalog):
        computed = compute_rows(attack_catalog, [_test(platforms=("windows", "linux"))], {}, {})
        assert (computed.rows[("T1059.001", "linux")].attack_platform,
                computed.rows[("T1059.001", "windows")].attack_platform) == (False, True)
        # the parent's rows include its sub-techniques' platforms
        parent = computed.rows[("T1059", "linux")]
        assert (parent.state, parent.own_state, parent.attack_platform, parent.tests_total) == (
            "untested", "none", False, 1)

    def test_a_platform_the_test_has_a_run_on_counts(self, attack_catalog):
        computed = compute_rows(attack_catalog, [_test()], {(GUID, "linux"): _evaluation(TestState.FAILING),
                                                            (GUID, ""): _evaluation(TestState.FAILING)}, {})
        assert computed.rows[("T1059.001", "linux")].state == "failing"
        assert ("T1059.001", "") not in computed.rows

    def test_manual_reaches_every_platform_but_not_the_sub_techniques(self, attack_catalog):
        computed = compute_rows(attack_catalog, [], {}, {SIGNATURE: _tag(SIGNATURE, "T1059")})
        states = _states(computed)
        assert states[("T1059", "windows")] == states[("T1059", "macos")] == ("manual", "manual")
        assert states[("T1059.001", "windows")] == states[("T1059.002", "macos")] == ("none", "none")

    def test_a_sub_technique_tag_rolls_up(self, attack_catalog):
        computed = compute_rows(attack_catalog, [], {}, {SIGNATURE: _tag(SIGNATURE, "T1059.002"),
                                                         OTHER_SIGNATURE: _tag(OTHER_SIGNATURE, "T1059")})
        states = _states(computed)
        assert states[("T1059.002", "macos")] == ("manual", "manual")
        assert states[("T1059", "macos")] == ("manual", "manual")
        assert computed.rows[("T1059", "macos")].manual_signatures == 2
        assert computed.rows[("T1059", "windows")].manual_signatures == 1

    def test_tags_that_do_not_count(self, attack_catalog):
        computed = compute_rows(attack_catalog, [], {}, {
            SIGNATURE: _tag(SIGNATURE, "T1059", counts=False, ignored=("mitre:TA0002", "mitre:{{ t }}"))})
        assert _states(computed)[("T1059", "windows")] == ("none", "none")
        assert computed.ignored_tags == 2

    def test_tags_the_worklist_resolved_remove_do_not_count(self, attack_catalog):
        tags = {SIGNATURE: _tag(SIGNATURE, "T1547", "T1086"), OTHER_SIGNATURE: _tag(OTHER_SIGNATURE, "T1547")}
        computed = compute_rows(attack_catalog, [], {}, tags,
                                excluded=frozenset({(SIGNATURE, "T1547"), (SIGNATURE, "T1059.001")}))
        assert computed.rows[("T1547", "windows")].manual_signatures == 1
        # excluded by the technique the tag counts as
        assert _states(computed)[("T1059.001", "windows")] == ("none", "none")

    def test_revoked_ids_count_as_their_successor(self, attack_catalog):
        computed = compute_rows(attack_catalog, [_test(technique="T1086")],
                                {(GUID, "windows"): _evaluation(TestState.VALIDATED)},
                                {SIGNATURE: _tag(SIGNATURE, "T1150")})
        assert computed.rows[("T1059.001", "windows")].state == "validated"
        assert ("T1086", "windows") not in computed.rows
        # T1150 was revoked by the deprecated T1099, which has rows while something names it
        deprecated = computed.rows[("T1099", "windows")]
        assert (deprecated.state, deprecated.catalog_status) == ("manual", "deprecated")

    def test_unknown_ids(self, attack_catalog):
        computed = compute_rows(attack_catalog, [_test(technique="T1234.001", technique_name="Custom"),
                                                 _test(OTHER_GUID, technique="not a technique")],
                                {}, {SIGNATURE: _tag(SIGNATURE, "T9999")})
        row = computed.rows[("T1234.001", "windows")]
        assert (row.state, row.catalog_status, row.technique_name, row.parent, row.attack_platform, row.tactics) == (
            "untested", "unknown", "Custom", "T1234", False, "[]")
        parent = computed.rows[("T1234", "windows")]
        assert (parent.state, parent.own_state, parent.catalog_status, parent.technique_name) == (
            "untested", "none", "unknown", None)
        # an unknown tag doesn't count; it is counted
        assert not any(technique == "T9999" for technique, _ in computed.rows)
        assert computed.unknown_tags == 1
        assert computed.skipped_tests == [OTHER_GUID]

    def test_measured_signatures_and_last_review(self, attack_catalog):
        later = T0 + timedelta(days=1)
        tests = [_test(GUID), _test(OTHER_GUID, technique="T1059")]
        evaluations = {(GUID, "windows"): _evaluation(TestState.VALIDATED, expected=[SIGNATURE]),
                       (OTHER_GUID, "windows"): _evaluation(TestState.FAILING, reviewed_at=later,
                                                            expected=[SIGNATURE, OTHER_SIGNATURE])}
        computed = compute_rows(attack_catalog, tests, evaluations, {})
        parent = computed.rows[("T1059", "windows")]
        assert (parent.measured_signatures, parent.last_reviewed_at, parent.tests_total) == (2, later, 2)
        sub = computed.rows[("T1059.001", "windows")]
        assert (sub.measured_signatures, sub.last_reviewed_at) == (1, T0)


#
# signature_techniques
#

@pytest.mark.integration
class TestSignatureTechniques:
    def test_hunt_tags(self, hunt_dir, yara_dir):
        write_hunt(hunt_dir, "h1", enabled=False, name="hunt h1",
                   tags=["mitre:t1059.001", "MITRE:T1547", "mitre:TA0002", "mitre:{{ technique }}", "phishing"])
        write_hunt(hunt_dir, "h2", tags=["phishing"])
        result = signature_techniques()
        assert list(result) == ["h1"]
        assert result["h1"] == SignatureTags("h1", "hunt", "hunt h1", False, ("T1059.001", "T1547"),
                                             ("mitre:TA0002", "mitre:{{ technique }}"))

    def test_yara_tags(self, hunt_dir, yara_dir):
        write_hunt(hunt_dir, "shared", tags=["mitre:T1059"])
        write_yara_rule(yara_dir, "on_rule", "on", mitre_attack="T1059.001")
        write_yara_rule(yara_dir, "off_rule", "off", mitre_attack="T1059.001", enabled="false")
        write_yara_rule(yara_dir, "qa_rule", "qa", mitre_attack="T1059.001", modifiers="qa")
        write_yara_rule(yara_dir, "untagged_rule", "untagged")
        write_yara_rule(yara_dir, "shared_rule", "shared", mitre_attack="T1547")
        result = signature_techniques()
        assert {uuid: (tags.family, tags.name, tags.counts, tags.declared) for uuid, tags in result.items()} == {
            "on": ("yara", "on_rule", True, ("T1059.001",)),
            "off": ("yara", "off_rule", False, ("T1059.001",)),
            "qa": ("yara", "qa_rule", False, ("T1059.001",)),
            # a uuid both use is the hunt's
            "shared": ("hunt", "shared", True, ("T1059",)),
        }

    def test_an_inventory_error_raises(self, hunt_dir, yara_dir, monkeypatch):
        missing = str(yara_dir / "missing")
        monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", missing)
        with pytest.raises(SignatureTagsUnavailable, match=f"{missing} is not a directory"):
            signature_techniques()

    def test_no_yara_location_is_not_an_error(self, hunt_dir, monkeypatch):
        write_hunt(hunt_dir, "h1", tags=["mitre:T1059"])
        # no service_yara configuration at all, which leaves no yara location
        monkeypatch.setitem(LOCATION_RESOLVERS, SignatureType.YARA, lambda: [])
        assert list(signature_techniques()) == ["h1"]


#
# refresh_coverage
#

@pytest.fixture
def refreshable(hunt_dir, yara_dir, monkeypatch, attack_catalog) -> Path:
    """The hunt rule dir; there are no signatures until a test writes one."""
    monkeypatch.setattr(coverage, "get_attack_catalog", lambda: attack_catalog)
    add_test_host("win10-01")
    return hunt_dir


@pytest.fixture
def user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


def _rows() -> dict[tuple[str, str], SVSCoverage]:
    with private_transaction() as session:
        rows = {(row.technique, row.platform): row for row in session.execute(select(SVSCoverage)).scalars()}
        session.expunge_all()
    return rows


def _state() -> SVSCoverageState:
    with private_transaction() as session:
        state = session.get(SVSCoverageState, STATE_ID)
        session.expunge_all()
    return state


def _validated_run(guid: str, user_id: int):
    """A reviewed run of guid on win10-01 that hit SIGNATURE, which is expected of it."""
    expectations.set_expectation(guid, SIGNATURE, "expected", user_id, platform="windows")
    run = started_run(guid)
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(state="reviewed", reviewed_at=T0))
    db.commit()
    with private_transaction() as session:
        session.add(SVSRunResult(run_id=run.id, signature_uuid=SIGNATURE, status="hit", reviewed_status="hit"))


@pytest.mark.integration
class TestRefresh:
    def test_refresh_writes_only_what_changed(self, refreshable, user_id):
        add_catalog_test(GUID)
        first = refresh_coverage("test")
        assert (first.rows, first.changed, first.inserted, first.retired) == (5, 5, 5, 0)
        state = _state()
        assert (state.attack_release, state.rows, state.changed, state.error) == ("v99.0", 5, 5, None)
        assert _rows()[("T1059.001", "windows")].state == "untested"

        before = {key: row.updated_at for key, row in _rows().items()}
        again = refresh_coverage("test")
        assert (again.rows, again.changed) == (5, 0)
        assert {key: row.updated_at for key, row in _rows().items()} == before

        _validated_run(GUID, user_id)
        result = refresh_coverage("test", now=T0 + timedelta(hours=1))
        assert result.changed == 2
        rows = _rows()
        assert (rows[("T1059.001", "windows")].state, rows[("T1059.001", "windows")].state_changed_at) == (
            "validated", T0 + timedelta(hours=1))
        assert (rows[("T1059", "windows")].state, rows[("T1059", "windows")].own_state) == ("validated", "none")
        assert rows[("T1059", "macos")].updated_at == before[("T1059", "macos")]

    def test_removed_tests_do_not_count(self, refreshable):
        add_catalog_test(GUID, removed=True)
        refresh_coverage("test")
        assert _rows()[("T1059.001", "windows")].state == "none"

    def test_rows_retire_and_come_back(self, refreshable):
        add_catalog_test(GUID, technique="T1234.001")
        refresh_coverage("test")
        assert _rows()[("T1234.001", "windows")].retired_at is None

        db = get_db()
        db.execute(update(SVSCatalogTest).where(SVSCatalogTest.guid == GUID).values(removed_at=datetime.now()))
        db.commit()
        result = refresh_coverage("test")
        rows = _rows()
        assert result.retired == 2
        assert rows[("T1234.001", "windows")].retired_at is not None
        assert rows[("T1234", "windows")].retired_at is not None
        assert _state().retired == 2

        db.execute(update(SVSCatalogTest).where(SVSCatalogTest.guid == GUID).values(removed_at=None))
        db.commit()
        result = refresh_coverage("test")
        assert (result.changed, result.retired) == (2, 0)
        assert _rows()[("T1234.001", "windows")].retired_at is None

    def test_tags_count(self, refreshable):
        write_hunt(refreshable, SIGNATURE, tags=["mitre:T1547", "mitre:T9999", "mitre:TA0002"])
        refresh_coverage("test")
        assert _rows()[("T1547", "windows")].state == "manual"
        state = _state()
        assert (state.unknown_tags, state.ignored_tags) == (1, 1)

    def test_a_failure_changes_nothing_and_is_recorded(self, refreshable, monkeypatch):
        def unavailable():
            raise SignatureTagsUnavailable("unable to load yara signatures from rules: boom")

        monkeypatch.setattr(coverage, "signature_techniques", unavailable)
        with pytest.raises(SignatureTagsUnavailable):
            refresh_coverage("test")
        assert _rows() == {}
        state = _state()
        assert (state.refreshed_at, state.error) == (None, "unable to load yara signatures from rules: boom")

        monkeypatch.setattr(coverage, "signature_techniques", signature_techniques)
        refresh_coverage("test")
        assert _state().error is None

    def test_the_refresher_survives_a_failure(self, refreshable, monkeypatch):
        monkeypatch.setattr(coverage, "signature_techniques",
                            lambda: (_ for _ in ()).throw(SignatureTagsUnavailable("boom")))
        CoverageRefresher(None).run_once()
        assert _state().error == "boom"

    def test_the_service_refreshes_coverage(self, refreshable):
        SVSService().start_single_threaded()
        assert len(_rows()) == 5

    def test_cli(self, refreshable, monkeypatch, capsys):
        monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
        assert cli_coverage_status(Namespace()) == 0
        assert "never been refreshed" in capsys.readouterr().out

        assert cli_coverage_refresh(Namespace(force=False)) == 0
        assert "not the primary node" in capsys.readouterr().out
        assert _rows() == {}

        assert cli_coverage_refresh(Namespace(force=True)) == 0
        assert "5 rows: 5 changed (5 new, 0 retired)" in capsys.readouterr().out

        assert cli_coverage_status(Namespace()) == 0
        out = capsys.readouterr().out
        assert "against ATT&CK v99.0" in out
        assert "windows: 3 none" in out

    def test_cli_reports_a_failure(self, refreshable, monkeypatch, capsys):
        monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
        monkeypatch.setattr(coverage, "signature_techniques",
                            lambda: (_ for _ in ()).throw(SignatureTagsUnavailable("boom")))
        assert cli_coverage_refresh(Namespace(force=False)) == 1
        assert "coverage refresh failed: boom" in capsys.readouterr().out
        cli_coverage_status(Namespace())
        assert "the latest refresh failed: boom" in capsys.readouterr().out


#
# write_snapshot
#

def _snapshots() -> dict[tuple[date, str, str], SVSCoverageSnapshot]:
    with private_transaction() as session:
        rows = {(row.snapshot_date, row.technique, row.platform): row
                for row in session.execute(select(SVSCoverageSnapshot)).scalars()}
        session.expunge_all()
    return rows


@pytest.mark.integration
class TestSnapshot:
    def test_a_snapshot_copies_the_live_rows(self, refreshable, user_id):
        add_catalog_test(GUID)
        _validated_run(GUID, user_id)
        result = write_snapshot("test", snapshot_date=DAY)
        assert (result.snapshot_date, result.attack_release, result.rows, result.deleted) == (DAY, "v99.0", 5, 0)

        snapshots = _snapshots()
        assert len(snapshots) == 5
        row = snapshots[(DAY, "T1059", "windows")]
        assert (row.attack_release, row.state, row.own_state, row.tests_total, row.tests_validated,
                row.measured_signatures, row.is_subtechnique) == ("v99.0", "validated", "none", 1, 1, 1, False)

    def test_a_second_snapshot_the_same_day_replaces_it(self, refreshable):
        add_catalog_test(GUID, technique="T1234.001")
        write_snapshot("test", snapshot_date=DAY)
        assert (DAY, "T1234.001", "windows") in _snapshots()
        before = _snapshots()[(DAY, "T1059", "windows")].updated_at

        # the test goes away: its rows retire, so they leave the day's snapshot
        db = get_db()
        db.execute(update(SVSCatalogTest).where(SVSCatalogTest.guid == GUID).values(removed_at=datetime.now()))
        db.commit()
        result = write_snapshot("test", snapshot_date=DAY)
        assert (result.rows, result.deleted) == (5, 2)
        snapshots = _snapshots()
        assert (DAY, "T1234.001", "windows") not in snapshots
        assert len(snapshots) == 5
        # a row that didn't change isn't rewritten
        assert snapshots[(DAY, "T1059", "windows")].updated_at == before

        # another day is another snapshot
        write_snapshot("test", snapshot_date=DAY + timedelta(days=1))
        assert len(_snapshots()) == 10

    def test_today_in_utc_by_default(self, refreshable):
        assert write_snapshot("test").snapshot_date == datetime.now(timezone.utc).date()

    def test_a_failed_refresh_writes_no_snapshot(self, refreshable, monkeypatch):
        monkeypatch.setattr(coverage, "signature_techniques",
                            lambda: (_ for _ in ()).throw(SignatureTagsUnavailable("boom")))
        with pytest.raises(SignatureTagsUnavailable):
            write_snapshot("test", snapshot_date=DAY)
        assert _snapshots() == {}

    def test_cli(self, refreshable, monkeypatch, capsys):
        monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
        assert cli_coverage_snapshot(Namespace(force=False)) == 0
        assert "not the primary node" in capsys.readouterr().out
        assert _snapshots() == {}

        assert cli_coverage_snapshot(Namespace(force=True)) == 0
        today = datetime.now(timezone.utc).date()
        assert f"snapshot of {today} against ATT&CK v99.0: 5 rows" in capsys.readouterr().out
        assert len(_snapshots()) == 5

        monkeypatch.setattr(coverage, "signature_techniques",
                            lambda: (_ for _ in ()).throw(SignatureTagsUnavailable("boom")))
        assert cli_coverage_snapshot(Namespace(force=True)) == 1
        assert "coverage snapshot failed: boom" in capsys.readouterr().out
