"""The SVS logging contract (docs/SVS.md, Part 5, *Logging contract*): every record about a run
carries svs_run, svs_test and svs_marker in extra, plus the fields of its row in the table. The
table is a contract; this keeps a refactor from dropping a field."""

import logging
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import update

from saq.alert_routing import reset_alert_routers
from saq.analysis.root import RootAnalysis
from saq.constants import F_HOSTNAME
from saq.database.model import SVSRun
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.svs.attribution import clear_caches, evaluate, write_attributions

from saq.svs.hosts import build_spec, create_host
from saq.svs.refusals import Caller
from saq.svs.runs import Registration, RegistrationRefused, TargetSpec, cancel, executed, register, run_timers, start
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LAUNCHER = Caller(name="art-launcher", address="10.1.2.3")
T0 = datetime(2026, 10, 14, 12, 0, 0)

RUN_FIELDS = ("svs_run", "svs_test", "svs_marker")
TRANSITION_FIELDS = RUN_FIELDS + ("from_state", "to_state", "actor")
LAUNCHER_CALL_FIELDS = RUN_FIELDS + ("launcher", "call", "outcome")
REFUSAL_FIELDS = ("caller", "host", "reason", "launcher", "svs_test")


@pytest.fixture(autouse=True)
def setup(no_hunts):
    add_catalog_test(GUID)
    create_host(build_spec("win10-01"), None)


def _registration(hostname: str = "win10-01") -> Registration:
    return Registration(test_guid=GUID, targets=[TargetSpec(hostname)], launcher="art")


def _records(caplog, prefix: str) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.getMessage().startswith(prefix)]


def _assert_fields(record: logging.LogRecord, fields: tuple[str, ...]):
    missing = [name for name in fields if not hasattr(record, name)]
    assert not missing, f"{record.getMessage()!r} lacks {missing}"


def test_lifecycle_transitions(caplog):
    with caplog.at_level(logging.INFO):
        first = register(_registration(), LAUNCHER, now=T0)
        start(first.uuid, LAUNCHER, now=T0)
        executed(first.uuid, LAUNCHER, 1, now=T0)
        second = register(_registration(), LAUNCHER, now=T0)
        cancel(second.uuid, LAUNCHER, now=T0)
        third = register(_registration(), LAUNCHER, now=T0)
        start(third.uuid, LAUNCHER, now=T0)
        run_timers(T0 + timedelta(days=2))

    records = _records(caplog, "svs run ")
    assert {(r.from_state, r.to_state) for r in records} == {
        (None, "created"), ("created", "started"), ("started", "error"), ("created", "canceled"),
        ("canceled", "closed"), ("started", "ended"), ("error", "closed")}
    for record in records:
        assert record.levelno == logging.INFO
        _assert_fields(record, TRANSITION_FIELDS)
    assert {r.svs_run for r in records} == {first.uuid, second.uuid, third.uuid}
    assert {r.actor for r in records} == {"art-launcher", "svs"}


def test_launcher_calls(caplog):
    with caplog.at_level(logging.INFO):
        run = register(_registration(), LAUNCHER)
        start(run.uuid, LAUNCHER)
        executed(run.uuid, LAUNCHER, 0)
        cancel(run.uuid, LAUNCHER)

    records = _records(caplog, "svs launcher call")
    assert [(r.call, r.outcome) for r in records] == [
        ("register", "created"), ("start", "started"), ("executed", "recorded"), ("cancel", "canceled")]
    for record in records:
        assert record.levelno == logging.INFO and record.svs_run == run.uuid
        _assert_fields(record, LAUNCHER_CALL_FIELDS)


def test_a_refused_registration(caplog):
    with caplog.at_level(logging.INFO), pytest.raises(RegistrationRefused):
        register(_registration("prod-dc-01"), LAUNCHER)

    (refusal,) = _records(caplog, "svs run registration refused")
    assert refusal.levelno == logging.WARNING and refusal.caller == "art-launcher"
    _assert_fields(refusal, REFUSAL_FIELDS)

    (call,) = _records(caplog, "svs launcher call")
    assert (call.levelno, call.call, call.outcome, call.caller) == (logging.WARNING, "register", "refused", "art-launcher")


#
# attribution (saq.svs.attribution, saq.svs.routing)
#

SIGHTING_FIELDS = ("svs_marker", "alert_uuid", "scan_point", "result")
DECISION_FIELDS = RUN_FIELDS + ("alert_uuid", "stage", "decision", "queue", "confidence")
ATTRIBUTION_FIELDS = RUN_FIELDS + ("alert_uuid", "detection", "confidence", "late", "source")


@pytest.fixture
def routed(monkeypatch):
    reset_alert_routers()
    monkeypatch.setattr("saq.database.util.alert.submit_payload_task", lambda alert_uuid: None)
    yield
    reset_alert_routers()


def _alert(host: str, details: dict, detections=("hunt hit",)) -> RootAnalysis:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now())
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    root.details = details
    for description in detections:
        root.add_detection_point(description)
    root.save()
    ALERT(root)
    return root


def _started():
    run = register(_registration(), LAUNCHER, now=datetime.now() - timedelta(minutes=1))
    run = start(run.uuid, LAUNCHER, now=datetime.now() - timedelta(minutes=1))
    clear_caches()
    return run


def test_attribution(caplog, routed):
    run = _started()
    with caplog.at_level(logging.INFO):
        root = _alert("win10-01", {"cmd": run.marker})

    (sighting,) = _records(caplog, "svs marker ")
    assert sighting.levelno == logging.INFO and sighting.result == "attributed" and sighting.svs_run == run.uuid
    _assert_fields(sighting, SIGHTING_FIELDS + RUN_FIELDS)

    (decision,) = _records(caplog, "svs router decision")
    assert (decision.decision, decision.stage, decision.confidence) == ("routed", "pre_insert", "marker")
    _assert_fields(decision, DECISION_FIELDS)

    (written,) = _records(caplog, "svs attribution written")
    assert written.alert_uuid == root.uuid and written.source == "router"
    _assert_fields(written, ATTRIBUTION_FIELDS)

    caplog.clear()
    root.detections.clear()
    with caplog.at_level(logging.INFO):
        write_attributions(root.uuid, evaluate(root, datetime.now()))
    (removed,) = _records(caplog, "svs attribution removed")
    _assert_fields(removed, ATTRIBUTION_FIELDS)


def test_a_mismatch(caplog, routed):
    run = _started()
    with caplog.at_level(logging.INFO):
        _alert("prod-dc-01", {"cmd": run.marker})

    (sighting,) = _records(caplog, "svs marker ")
    assert (sighting.levelno, sighting.result) == (logging.WARNING, "other host")
    _assert_fields(sighting, SIGHTING_FIELDS + RUN_FIELDS)
    (decision,) = _records(caplog, "svs router decision")
    assert decision.decision == "mismatch" and decision.svs_run == run.uuid


def test_a_refused_context_attribution(caplog, routed):
    first, second = _started(), _started()
    with caplog.at_level(logging.INFO):
        root = _alert("win10-01", {})

    (refused,) = _records(caplog, "svs context attribution")
    assert refused.levelno == logging.WARNING
    assert sorted(refused.candidate_runs) == sorted([first.uuid, second.uuid])
    assert refused.alert_uuid == root.uuid
    # it is about two runs, so it names neither as its own
    assert not hasattr(refused, "svs_run")


CLOSED_ALERTS_FIELDS = RUN_FIELDS + ("alert_uuids", "left_alone", "late", "actor")


def test_alerts_closed_with_their_run(caplog, routed):
    run = _started()
    root = _alert("win10-01", {"cmd": run.marker})
    cancel(run.uuid, LAUNCHER)
    with caplog.at_level(logging.INFO):
        run_timers(now=run.attribution_ends_at + timedelta(seconds=1))

    (closed,) = _records(caplog, f"svs run {run.uuid}: 1 alerts closed")
    assert closed.alert_uuids == [root.uuid] and closed.late is False
    _assert_fields(closed, CLOSED_ALERTS_FIELDS)


def test_a_run_changed_since_review(caplog, routed):
    run = _started()
    db = get_db()
    db.execute(update(SVSRun).where(SVSRun.id == run.id).values(state="reviewed"))
    db.commit()
    with caplog.at_level(logging.INFO):
        root = _alert("win10-01", {"cmd": run.marker})

    (changed,) = _records(caplog, f"svs run {run.uuid} changed since review")
    assert changed.alert_uuid == root.uuid
    _assert_fields(changed, RUN_FIELDS + ("alert_uuid",))
