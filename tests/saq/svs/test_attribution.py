"""Attributing alerts to test runs (saq.svs.attribution, docs/SVS_RUNS.md, *Attribution*)."""

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pymysql
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from saq.analysis.analysis import Analysis
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import F_FQDN, F_HOSTNAME, F_IPV4, F_TEST, F_URL
from saq.database import private_session
from saq.database.model import SVSAttribution, SVSRun, SVSRunEvent, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.environment import get_local_timezone
from saq.signatures.builtin import SVS_MARKER_MISMATCH, SVS_REGISTRATION_REFUSED
from saq.svs import attribution
from saq.svs.attribution import (
    AlertHosts,
    RunSnapshot,
    Sighting,
    TargetSnapshot,
    alert_event_time,
    alert_hosts,
    analysis_sightings,
    attribution_open,
    context_claimant,
    evaluate,
    find_markers_in_data,
    record_delta_sightings,
    resolve_markers,
    runs_in_window,
    save_sightings,
    saved_sightings,
    tree_sightings,
    write_attributions,
)
from saq.svs.constants import (
    ROUTER_ACTOR,
    SIGHTINGS_EXTENSION,
    AttributionConfidence,
    AttributionSource,
    MarkerResult,
    RunEventKind,
    RunState,
    ScanPoint,
    SVSStatus,
)
from saq.svs.expectations import set_test_settings
from saq.svs.marker_rule import MARKER_RULE_NAME
from saq.svs.markers import new_marker
from saq.svs.runs import Registration, TargetSpec, register, start
from tests.saq.svs.conftest import LAUNCHER, add_catalog_test, add_test_host, started_run

MARKER = "svs-" + "a" * 26
OTHER_MARKER = "svs-" + "b" * 26
T0 = datetime(2026, 10, 14, 12, 0, 0)
GUID = "aaaaaaaa-1111-4111-8111-111111111111"


class ChildAnalysis(Analysis):
    pass


def _run(host: str = "win10-01", started: Optional[datetime] = T0) -> RunSnapshot:
    """A run of GUID against host, started at started (None: registered and never started), as
    attribution reads it. Its windows are the floor and the default extra hours: 1 and 25 hours."""
    run = register(Registration(test_guid=GUID, targets=[TargetSpec(host)], launcher="art"), LAUNCHER,
                   now=started or T0)
    if started is not None:
        run = start(run.uuid, LAUNCHER, now=started)
    return resolve_markers([run.marker])[run.marker]


def _person_row(run: RunSnapshot, alert_uuid: str, content_hash: str, *, manual: bool = False,
                removed: bool = False) -> None:
    """A row a person left: a hand attribution (manual), or a router row a person removed."""
    with private_transaction() as session:
        user_id = session.execute(select(User.id).where(User.username == "unittest")).scalar_one()
        session.add(SVSAttribution(
            run_id=run.id, alert_uuid=alert_uuid, content_hash=content_hash, signature_uuid=str(uuid.uuid4()),
            confidence=AttributionConfidence.MARKER.value,
            source=AttributionSource.MANUAL.value if manual else AttributionSource.ROUTER.value,
            actor="unittest", actor_user_id=user_id if manual else None, created_at=datetime.now(),
            removed_at=datetime.now() if removed else None, removed_by="unittest" if removed else None,
            removed_by_user_id=user_id if removed else None))


def _tree():
    """A hunt-shaped root on win10-01, with a file observable carrying an analysis and a sibling URL:

        root ── hostname win10-01
             ├─ test "parent" ── ChildAnalysis ── test "child"
             └─ url http://example.com/
    """
    root = RootAnalysis(uuid=str(uuid.uuid4()))
    root.add_observable_by_spec(F_HOSTNAME, "win10-01")
    parent = root.add_observable_by_spec(F_TEST, "parent")
    analysis = ChildAnalysis()
    parent.add_analysis(analysis)
    child = analysis.add_observable_by_spec(F_TEST, "child")
    url = root.add_observable_by_spec(F_URL, "http://example.com/")
    return root, parent, child, url


#
# finding markers
#

@pytest.mark.unit
class TestFindingMarkers:
    def test_json_shaped_data(self):
        data = {"events": [{"cmd": f"whoami & REM {MARKER}"}, {"n": 1}], "other": ("x", f"<# {OTHER_MARKER.upper()} #>")}
        assert find_markers_in_data(data) == [MARKER, OTHER_MARKER]

    def test_bytes_are_read_as_match_data(self):
        assert find_markers_in_data([f" {MARKER} ".encode("utf-16-le")]) == [MARKER]

    def test_the_marker_rule_is_file_contents(self):
        details = {"scan_results": [
            {"rule": MARKER_RULE_NAME, "strings": [(0, "$marker", f" {MARKER}\n".encode())]},
            {"rule": "other_rule", "strings": [[4, "$s", f"cmd {OTHER_MARKER}"]]},
        ]}
        sightings = analysis_sightings(details, "obs", "yara_scanner_v3_4")
        assert sightings == [Sighting(MARKER, "obs", ScanPoint.FILE_CONTENTS, "yara_scanner_v3_4"),
                             Sighting(OTHER_MARKER, "obs", ScanPoint.ANALYSIS, "yara_scanner_v3_4")]

    def test_the_marker_rule_after_a_save(self):
        """Saved and loaded, a match is [offset, identifier, str], NULs and all."""
        wide = f" {MARKER} ".encode("utf-16-le").decode("latin-1")
        details = {"scan_results": [{"rule": MARKER_RULE_NAME, "strings": [[0, "$marker", wide]]}]}
        assert [s.scan_point for s in analysis_sightings(details, None, None)] == [ScanPoint.FILE_CONTENTS]

    def test_the_tree(self):
        root, parent, child, url = _tree()
        root.details = {"events": [{"cmd": f"powershell <# {MARKER} #>"}]}
        root.add_observable_by_spec(F_TEST, f"x {OTHER_MARKER}")
        child.add_detection_point(f"saw {OTHER_MARKER}")

        sightings = tree_sightings(root)
        assert Sighting(MARKER, None, ScanPoint.ROOT_DETAILS) in sightings
        assert any(s.marker == OTHER_MARKER and s.scan_point == ScanPoint.OBSERVABLE for s in sightings)
        assert Sighting(OTHER_MARKER, child.uuid, ScanPoint.DETECTION) in sightings

    def test_saved_sightings_of_observables_that_are_gone_are_dropped(self):
        root, parent, child, url = _tree()
        save_sightings(root, [Sighting(MARKER, child.uuid, ScanPoint.ANALYSIS, "m"),
                              Sighting(OTHER_MARKER, str(uuid.uuid4()), ScanPoint.ANALYSIS, "m")])
        assert [s.marker for s in tree_sightings(root)] == [MARKER]

    def test_saving_dedupes_and_caps(self, monkeypatch):
        root = RootAnalysis(uuid=str(uuid.uuid4()))
        sighting = Sighting(MARKER, None, ScanPoint.ANALYSIS, "m")
        assert save_sightings(root, [sighting, sighting]) == 1
        assert save_sightings(root, [sighting]) == 0

        monkeypatch.setattr(get_config().svs.attribution, "max_sightings", 2)
        assert save_sightings(root, [Sighting(new_marker(), None, ScanPoint.ANALYSIS) for _ in range(3)]) == 1
        assert len(root.extensions[SIGHTINGS_EXTENSION]) == 2
        assert saved_sightings(root)[0] == sighting


#
# hosts and time
#

@pytest.mark.unit
class TestHosts:
    def test_the_hosts_of_an_alert(self):
        root = RootAnalysis(uuid=str(uuid.uuid4()))
        root.add_observable_by_spec(F_HOSTNAME, "WIN10-01")
        root.add_observable_by_spec(F_FQDN, "web.example.com")
        root.add_observable_by_spec(F_IPV4, "10.0.0.5")
        root.add_observable_by_spec(F_HOSTNAME, "not a host")
        hosts = alert_hosts(root)
        assert hosts.names == {("win10-01", None), ("web", "web.example.com")}
        assert hosts.ips == {"10.0.0.5"}

    @pytest.mark.parametrize("names,ips,target,expected", [
        ({("win10-01", None)}, set(), TargetSnapshot("win10-01", None), True),
        ({("win10-01", None)}, set(), TargetSnapshot("win10-01", "win10-01.lab.example"), True),
        ({("win10-01", "win10-01.lab.example")}, set(), TargetSnapshot("win10-01", "win10-01.lab.example"), True),
        # a production host that shares the short name in another domain
        ({("win10-01", "win10-01.corp.example")}, set(), TargetSnapshot("win10-01", "win10-01.lab.example"), False),
        ({("win10-01", "win10-01.corp.example")}, set(), TargetSnapshot("win10-01", None), True),
        ({("win10-02", None)}, set(), TargetSnapshot("win10-01", None), False),
        (set(), {"10.0.0.5"}, TargetSnapshot("win10-01", None, frozenset({"10.0.0.5"})), True),
        (set(), {"10.0.0.6"}, TargetSnapshot("win10-01", None, frozenset({"10.0.0.5"})), False),
    ])
    def test_involvement(self, names, ips, target, expected):
        assert AlertHosts(names, ips).involves(target) is expected

    def test_event_time(self):
        root = RootAnalysis(uuid=str(uuid.uuid4()))
        assert alert_event_time(root, T0) == T0
        aware = datetime(2026, 10, 14, 16, 0, 0, tzinfo=timezone.utc)
        root.event_time = aware
        assert alert_event_time(root, T0) == aware.astimezone(get_local_timezone()).replace(tzinfo=None)


#
# evaluation
#

@pytest.mark.integration
class TestEvaluate:
    @pytest.fixture(autouse=True)
    def setup(self, no_hunts):
        add_catalog_test(GUID)
        add_test_host("win10-01")
        add_test_host("srv-01")

    def test_a_marker_in_the_alerts_details_attributes_everything(self):
        run = _run()
        root, parent, child, url = _tree()
        root.details = {"events": [{"cmd": f"whoami & REM {run.marker}"}]}
        root.add_detection_point("hunt hit")
        url.add_detection_point("bad url")

        evaluation = evaluate(root, T0 + timedelta(minutes=5))
        assert evaluation.status == SVSStatus.TEST
        assert evaluation.routed
        assert evaluation.judgements[0].result == MarkerResult.ATTRIBUTED
        assert {a.content_hash for a in evaluation.attributions} == {d.content_hash for d in evaluation.detections}
        assert all(a.run == run and a.confidence == AttributionConfidence.MARKER and not a.late
                   for a in evaluation.attributions)
        assert {a.scan_point for a in evaluation.attributions} == {ScanPoint.ROOT_DETAILS}

    def test_a_marker_attributes_its_own_branch(self):
        """Up (the parent and the root's own detections) and down, not the sibling URL."""
        run = _run()
        root, parent, child, url = _tree()
        root.add_detection_point("hunt hit")
        parent.add_detection_point("parent hit")
        child.add_detection_point("child hit")
        url.add_detection_point("bad url")
        save_sightings(root, [Sighting(run.marker, child.uuid, ScanPoint.FILE_CONTENTS, "yara")])

        evaluation = evaluate(root, T0)
        assert evaluation.status == SVSStatus.PARTIAL
        assert not evaluation.routed
        attributed = {a.content_hash for a in evaluation.attributions}
        by_description = {dp.description: h for h, dp in _hashes(root).items()}
        assert attributed == {by_description["hunt hit"], by_description["parent hit"], by_description["child hit"]}

    def test_a_marker_beneath_a_detection_attributes_it(self):
        run = _run()
        root, parent, child, url = _tree()
        parent.add_detection_point("parent hit")
        analysis = ChildAnalysis()
        child.add_analysis(analysis)
        analysis.add_observable_by_spec(F_TEST, f"deeper {run.marker}")

        assert evaluate(root, T0).status == SVSStatus.TEST

    # the run whose marker it is and a run context would claim overlap on one host
    @pytest.mark.usefixtures("overlapping_runs")
    @pytest.mark.parametrize("run,result", [
        (None, MarkerResult.UNKNOWN),
        ({"host": "srv-01"}, MarkerResult.OTHER_HOST),
        ({"started": None}, MarkerResult.OUTSIDE_WINDOW),
        ({"started": T0 + timedelta(minutes=1)}, MarkerResult.OUTSIDE_WINDOW),
        ({"started": T0 - timedelta(hours=26)}, MarkerResult.OUTSIDE_WINDOW),
    ])
    def test_a_marker_that_does_not_agree_is_a_mismatch(self, run, result):
        marker = _run(**run).marker if run is not None else MARKER
        # a run on the same host whose window covers the alert: context would claim it
        _run()
        root, parent, child, url = _tree()
        root.details = {"cmd": marker}
        root.add_detection_point("hunt hit")

        evaluation = evaluate(root, T0)
        assert evaluation.status == SVSStatus.MISMATCH
        assert [(j.marker, j.result) for j in evaluation.mismatches] == [(marker, result)]
        assert evaluation.attributions == []

    def test_one_disagreeing_marker_ends_attribution_for_the_whole_alert(self):
        run = _run()
        root, parent, child, url = _tree()
        root.details = {"a": run.marker, "b": OTHER_MARKER}
        root.add_detection_point("hunt hit")

        evaluation = evaluate(root, T0)
        assert evaluation.status == SVSStatus.MISMATCH
        assert evaluation.attributions == []

    def test_late(self):
        run = _run()
        root, parent, child, url = _tree()
        root.details = {"cmd": run.marker}
        root.add_detection_point("hunt hit")

        (a,) = evaluate(root, T0 + timedelta(hours=2)).attributions
        assert a.late

    def test_context_with_exactly_one_candidate(self):
        root, parent, child, url = _tree()
        root.add_detection_point("hunt hit")
        url.add_detection_point("bad url")
        run = _run()
        _run(host="srv-01")

        evaluation = evaluate(root, T0)
        assert evaluation.status == SVSStatus.TEST_CONTEXT
        assert evaluation.routed
        assert evaluation.confidence == AttributionConfidence.CONTEXT
        assert {a.run.id for a in evaluation.attributions} == {run.id}
        assert len(evaluation.attributions) == 2

    @pytest.mark.parametrize("signature", [SVS_REGISTRATION_REFUSED, SVS_MARKER_MISMATCH])
    def test_the_svs_built_ins_are_never_attributed(self, signature):
        root, parent, child, url = _tree()
        root.add_detection_point("svs built-in", signature_uuid=signature.uuid)
        _run()

        evaluation = evaluate(root, T0)
        assert evaluation.detections == []
        assert evaluation.status is None
        assert evaluation.attributions == []

    @pytest.mark.usefixtures("overlapping_runs")
    def test_context_with_two_overlapping_candidates_attributes_nothing(self):
        # runs registered before one run per host was enforced
        root, parent, child, url = _tree()
        root.add_detection_point("hunt hit")
        first, second = _run(), _run()

        evaluation = evaluate(root, T0)
        assert evaluation.status is None
        assert evaluation.attributions == []
        assert [r.id for r in evaluation.candidate_runs] == [first.id, second.id]

    def test_context_goes_to_the_run_on_the_host_after_the_one_before_released_it(self):
        first = _run()
        # the first run's claim ended with its observation window, at T0 + 1h
        second = _run(started=T0 + timedelta(hours=2))

        for event_time, run, late in [(T0 + timedelta(minutes=30), first, False),
                                      (T0 + timedelta(hours=2, minutes=30), second, False),
                                      # the first run's attribution window still covers it, as late
                                      (T0 + timedelta(hours=1, minutes=30), first, True)]:
            root, parent, child, url = _tree()
            root.add_detection_point("hunt hit")
            evaluation = evaluate(root, event_time)
            assert evaluation.status == SVSStatus.TEST_CONTEXT
            assert {(a.run.id, a.late) for a in evaluation.attributions} == {(run.id, late)}
            assert evaluation.candidate_runs == []

    @pytest.mark.usefixtures("overlapping_runs")
    def test_context_refuses_runs_whose_claims_overlap(self):
        set_test_settings(GUID, None, holds_host=True)
        first = _run()
        assert first.holds_host
        # inside the first run's claim, which a test that holds the host keeps for its attribution window
        second = _run(started=T0 + timedelta(hours=2))

        root, parent, child, url = _tree()
        root.add_detection_point("hunt hit")
        evaluation = evaluate(root, T0 + timedelta(hours=2, minutes=30))
        assert evaluation.attributions == []
        assert [r.id for r in evaluation.candidate_runs] == [first.id, second.id]

    def test_no_detections_no_attribution(self):
        run = _run()
        root, parent, child, url = _tree()
        root.details = {"cmd": run.marker}

        evaluation = evaluate(root, T0)
        assert evaluation.status is None
        assert evaluation.attributions == []

    def test_what_a_person_removed_stays_removed(self):
        run = _run()
        root, parent, child, url = _tree()
        root.details = {"cmd": run.marker}
        root.add_detection_point("hunt hit")
        url.add_detection_point("bad url")
        by_description = {dp.description: h for h, dp in _hashes(root).items()}
        # the person attributed the hunt hit by hand and removed the bad url
        _person_row(run, root.uuid, by_description["hunt hit"], manual=True)
        _person_row(run, root.uuid, by_description["bad url"], removed=True)

        evaluation = evaluate(root, T0)
        assert evaluation.status == SVSStatus.PARTIAL
        assert by_description["bad url"] not in {a.content_hash for a in evaluation.attributions}

    def test_a_run_a_person_disassociated_the_alert_from_attributes_nothing(self):
        run = _run()
        root, parent, child, url = _tree()
        root.details = {"cmd": run.marker}
        root.add_detection_point("hunt hit")
        (content_hash,) = _hashes(root)
        _person_row(run, root.uuid, content_hash, removed=True)
        # a detection added since the disassociation is not attributed either
        url.add_detection_point("bad url")

        evaluation = evaluate(root, T0)
        assert evaluation.attributions == [] and evaluation.status is None

    def test_a_persons_association_counts(self):
        run = _run()
        root, parent, child, url = _tree()
        root.add_detection_point("hunt hit")
        (content_hash,) = _hashes(root)
        _person_row(run, root.uuid, content_hash, manual=True)

        assert evaluate(root, T0).status == SVSStatus.TEST


def _soon() -> datetime:
    """An event time inside a run started just now (svs_runs times are stored to the second)."""
    return datetime.now() + timedelta(minutes=1)


def _hashes(root):
    from saq.analysis.detection_identity import detection_content_hash, node_identity
    return {detection_content_hash(node_identity(node), dp): dp for node, dp in root.detection_points_by_node()}


#
# against the database
#

@pytest.mark.integration
class TestDatabase:
    @pytest.fixture(autouse=True)
    def setup(self, no_hunts):
        add_catalog_test(GUID)
        add_test_host("win10-01", fqdn="win10-01.lab.example", ips=["10.0.0.5"])
        add_test_host("win10-02")

    def test_the_gate(self):
        assert not attribution_open()

        attribution.clear_caches()
        started_run(GUID)
        assert attribution_open()

        # a run long over does not hold it open
        get_db().execute(SVSRun.__table__.update().values(attribution_ends_at=datetime.now() - timedelta(minutes=1),
                                                          state=RunState.CLOSED.value))
        get_db().commit()
        attribution.clear_caches()
        assert not attribution_open()

    def test_a_registered_run_opens_the_gate_before_it_starts(self):
        from saq.svs.runs import Registration, TargetSpec, register
        from tests.saq.svs.conftest import LAUNCHER
        register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"), LAUNCHER)
        assert attribution_open()

    def test_the_gate_is_cached(self, monkeypatch):
        monkeypatch.setattr(get_config().svs.attribution, "gate_cache_seconds", 60)
        assert not attribution_open()
        started_run(GUID)  # clears the caches
        assert attribution_open()
        get_db().execute(SVSRun.__table__.delete())
        get_db().commit()
        assert attribution_open()

    @pytest.mark.usefixtures("overlapping_runs")
    def test_only_started_runs_are_cached(self):
        from saq.svs.runs import Registration, TargetSpec, register
        from tests.saq.svs.conftest import LAUNCHER
        assert resolve_markers([MARKER]) == {}

        created = register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"), LAUNCHER)
        # a miss is never cached: the run registered after it is found at once
        assert resolve_markers([created.marker])[created.marker].started_at is None
        assert created.marker not in attribution._caches.markers

        run = started_run(GUID)
        snapshot = resolve_markers([run.marker])[run.marker]
        assert snapshot.uuid == run.uuid
        assert snapshot.targets == (TargetSnapshot("win10-01", "win10-01.lab.example", frozenset({"10.0.0.5"})),)
        assert run.marker in attribution._caches.markers

    def test_the_executor_hook_saves_what_analysis_details_carry(self):
        started_run(GUID)
        root, parent, child, url = _tree()

        class Delta:
            analysis = {"details": {"stdout": f"ran {MARKER}"}}

        assert record_delta_sightings(root, parent, Delta(), "module_x") == 1
        assert saved_sightings(root) == [Sighting(MARKER, parent.uuid, ScanPoint.ANALYSIS, "module_x")]

    def test_the_executor_hook_does_nothing_while_the_gate_is_closed(self):
        root, parent, child, url = _tree()

        class Delta:
            analysis = {"details": {"stdout": f"ran {MARKER}"}}

        assert record_delta_sightings(root, parent, Delta(), "module_x") == 0
        assert not (root.extensions or {}).get(SIGHTINGS_EXTENSION)

    def test_runs_in_window(self):
        run = started_run(GUID)
        assert [r.uuid for r in runs_in_window(_soon())] == [run.uuid]
        assert runs_in_window(datetime.now() - timedelta(hours=1)) == []

    def test_evaluate_by_ip(self):
        run = started_run(GUID)
        root = RootAnalysis(uuid=str(uuid.uuid4()))
        root.add_observable_by_spec(F_IPV4, "10.0.0.5")
        root.add_detection_point(f"process ran {run.marker}")

        evaluation = evaluate(root, _soon())
        assert evaluation.status == SVSStatus.TEST
        assert evaluation.attributions[0].scan_point == ScanPoint.DETECTION

    def _rows(self, alert_uuid):
        with private_transaction() as session:
            return [(r.content_hash, r.removed_at is not None, r.removed_by, r.source) for r in session.execute(
                select(SVSAttribution).where(SVSAttribution.alert_uuid == alert_uuid)
                .order_by(SVSAttribution.content_hash)).scalars()]

    def _root(self, run):
        root = RootAnalysis(uuid=str(uuid.uuid4()))
        root.add_observable_by_spec(F_HOSTNAME, "win10-01")
        root.details = {"cmd": run.marker}
        root.add_detection_point("one")
        root.add_detection_point("two")
        return root

    def test_writing(self, caplog):
        run = started_run(GUID)
        root = self._root(run)

        evaluation = evaluate(root, _soon())
        result = write_attributions(root.uuid, evaluation)
        assert len(result.written) == 2
        assert [(removed, source) for _, removed, _, source in self._rows(root.uuid)] == [
            (False, "router"), (False, "router")]

        # the same evaluation changes nothing
        assert write_attributions(root.uuid, evaluate(root, _soon())).written == []

        # a detection that is gone is removed by the router ...
        root.detections.pop()
        result = write_attributions(root.uuid, evaluate(root, _soon()))
        assert len(result.removed) == 1
        assert sorted(removed for _, removed, _, _ in self._rows(root.uuid)) == [False, True]
        assert any(r.getMessage().startswith("svs attribution removed") for r in caplog.records)

        # ... and restored by it when it comes back
        root.add_detection_point("two")
        result = write_attributions(root.uuid, evaluate(root, _soon()))
        assert len(result.written) == 1
        assert [removed for _, removed, _, _ in self._rows(root.uuid)] == [False, False]

    def _reviewed_run(self):
        run = started_run(GUID)
        get_db().execute(SVSRun.__table__.update().where(SVSRun.id == run.id).values(
            state=RunState.REVIEWED.value, changed_since_review=False))
        get_db().commit()
        return run

    def test_alerts_of_one_run_written_at_once(self, monkeypatch):
        """Each write locks the run before its rows, so alerts of one run arriving together wait
        their turn instead of deadlocking (no retries here to hide one)."""
        monkeypatch.setattr(attribution, "WRITE_ATTEMPTS", 1)
        run = self._reviewed_run()
        roots = [self._root(run) for _ in range(8)]
        evaluations = [evaluate(root, _soon()) for root in roots]
        barrier = threading.Barrier(len(roots))
        errors = []

        def write(root, evaluation):
            try:
                barrier.wait()
                write_attributions(root.uuid, evaluation)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write, args=pair) for pair in zip(roots, evaluations)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert all(len(self._rows(root.uuid)) == 2 for root in roots)
        get_db().expire_all()
        assert get_db().get(SVSRun, run.id).changed_since_review

    def test_a_deadlock_is_tried_again(self, monkeypatch, caplog):
        monkeypatch.setattr(private_session.time, "sleep", lambda _: None)
        run = started_run(GUID)
        root = self._root(run)
        flag = attribution.flag_changed_since_review
        calls = []

        def deadlock_once(session, run_ids):
            calls.append(run_ids)
            if len(calls) == 1:
                raise OperationalError("UPDATE svs_runs", {}, pymysql.err.OperationalError(1213, "Deadlock found"))
            return flag(session, run_ids)

        monkeypatch.setattr(attribution, "flag_changed_since_review", deadlock_once)
        result = write_attributions(root.uuid, evaluate(root, _soon()))

        assert len(calls) == 2 and len(result.written) == 2
        assert len(self._rows(root.uuid)) == 2
        with private_transaction() as session:
            assert session.execute(select(func.count()).select_from(SVSRunEvent).where(
                SVSRunEvent.run_id == run.id, SVSRunEvent.kind == RunEventKind.ATTRIBUTED.value)).scalar() == 1
        assert any("trying again" in r.getMessage() for r in caplog.records)

    def test_a_deadlock_that_keeps_happening_raises(self, monkeypatch):
        """A deadlock is tried WRITE_ATTEMPTS times, then the router reports it (the retry itself
        is tested in tests/saq/database/test_private_session.py)."""
        monkeypatch.setattr(private_session.time, "sleep", lambda _: None)
        run = started_run(GUID)
        root = self._root(run)
        calls = []

        def fail(session, run_ids):
            calls.append(run_ids)
            raise OperationalError("UPDATE svs_runs", {}, pymysql.err.OperationalError(1213, "Deadlock found"))

        monkeypatch.setattr(attribution, "flag_changed_since_review", fail)
        with pytest.raises(OperationalError):
            write_attributions(root.uuid, evaluate(root, _soon()))
        assert len(calls) == attribution.WRITE_ATTEMPTS
        assert self._rows(root.uuid) == []

    def test_a_person_removal_is_never_undone(self):
        run = started_run(GUID)
        root = self._root(run)
        write_attributions(root.uuid, evaluate(root, _soon()))

        with private_transaction() as session:
            row = session.execute(select(SVSAttribution).where(SVSAttribution.alert_uuid == root.uuid)
                                  .order_by(SVSAttribution.id).limit(1)).scalar_one()
            row.removed_at = datetime.now()
            row.removed_by = "alice"
            row.removed_by_user_id = session.execute(select(User.id).where(User.username == "unittest")).scalar_one()

        # a person's removal blocks the run for the whole alert: the router removes its other row
        evaluation = evaluate(root, _soon())
        assert evaluation.status is None
        assert write_attributions(root.uuid, evaluation).written == []
        assert sorted((by or "") for _, _, by, _ in self._rows(root.uuid)) == ["alice", "svs"]

    def test_a_removal_by_a_user_named_like_the_router_is_still_a_persons(self):
        run = started_run(GUID)
        root = self._root(run)
        write_attributions(root.uuid, evaluate(root, _soon()))
        with private_transaction() as session:
            for row in session.execute(select(SVSAttribution).where(SVSAttribution.alert_uuid == root.uuid)).scalars():
                row.removed_at = datetime.now()
                row.removed_by = "svs"
                row.removed_by_user_id = session.execute(
                    select(User.id).where(User.username == "unittest")).scalar_one()

        assert write_attributions(root.uuid, evaluate(root, _soon())).written == []
        assert all(removed for _, removed, _, _ in self._rows(root.uuid))

    def test_a_mismatch_removes_what_the_router_wrote(self):
        run = started_run(GUID)
        root = self._root(run)
        write_attributions(root.uuid, evaluate(root, _soon()))

        root.details = {"cmd": run.marker, "other": "svs-" + "z" * 26}
        evaluation = evaluate(root, _soon())
        assert evaluation.status == SVSStatus.MISMATCH
        assert len(write_attributions(root.uuid, evaluation).removed) == 2
        assert {by for _, _, by, _ in self._rows(root.uuid)} == {ROUTER_ACTOR}


@pytest.mark.unit
class TestContextClaimant:
    @staticmethod
    def _snapshot(run_id: int, started: Optional[datetime], hours: int = 1, holds_host: bool = False) -> RunSnapshot:
        return RunSnapshot(id=run_id, uuid=str(run_id), test_guid=GUID, marker=MARKER, started_at=started,
                           observation_ends_at=started + timedelta(hours=hours) if started else None,
                           attribution_ends_at=started + timedelta(hours=hours + 24) if started else None,
                           holds_host=holds_host)

    def test_none_or_one(self):
        assert context_claimant([]) is None
        run = self._snapshot(1, T0)
        assert context_claimant([run]) is run

    def test_the_latest_run_when_the_others_released_the_host_before_it_started(self):
        first, second, third = (self._snapshot(1, T0), self._snapshot(2, T0 + timedelta(hours=2)),
                                self._snapshot(3, T0 + timedelta(hours=4)))
        assert context_claimant([third, first, second]) is third

    @pytest.mark.parametrize("first", [
        # its observation window ends as the second starts
        _snapshot(1, T0, hours=2),
        # it holds the host for its attribution window
        _snapshot(1, T0, holds_host=True),
    ])
    def test_none_when_claims_overlap(self, first):
        assert context_claimant([first, self._snapshot(2, T0 + timedelta(hours=2))]) is None
