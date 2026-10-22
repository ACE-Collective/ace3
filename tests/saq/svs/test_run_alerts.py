"""What happens to a run's alerts downstream of attribution (docs/SVS_RUNS.md): SIMULATED when the run
closes and for late alerts of a closed run, the attribution events of the run's event log, changed
since review, and the runs holding open alerts in Needs attention."""

import json
import logging
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from saq.alert_routing import reset_alert_routers
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import (
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_OPEN,
    DISPOSITION_SIMULATED,
    F_HOSTNAME,
    F_TEST,
)
from saq.database.model import Alert, Comment, SVSAttribution, SVSRun, SVSRunEvent, SVSRunResultState, User
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, set_dispositions
from saq.signatures.builtin import GENERIC
from saq.svs import association, runs
from saq.svs.attribution import evaluate, write_attributions
from saq.svs.constants import RunEventKind, RunState
from saq.svs.run_filters import needs_attention_condition, open_alerts_condition
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import LAUNCHER, add_catalog_test, add_test_host, started_run

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
YARA_RULE = "22222222-bbbb-4bbb-8bbb-222222222222"


@pytest.fixture(autouse=True)
def setup(no_hunts):
    reset_alert_routers()
    add_catalog_test(GUID)
    add_test_host("win10-01")
    yield
    reset_alert_routers()


@pytest.fixture
def run() -> SVSRun:
    return started_run(GUID, now=datetime.now() - timedelta(minutes=1))


def _root(alert_uuid: str, *, marker=None, host="win10-01", partial=False) -> RootAnalysis:
    root = create_root_analysis(uuid=alert_uuid, event_time=datetime.now())
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    if partial:
        marked = root.add_observable_by_spec(F_TEST, f"ran {marker}")
        marked.add_detection_point("test detection")
        other = root.add_observable_by_spec(F_TEST, "unrelated")
        other.add_detection_point("real detection")
    else:
        if marker:
            root.details = {"events": [{"command_line": f"whoami & REM {marker}"}]}
        root.add_detection_point("hunt hit")
    return root


def _alert(*, marker=None, host="win10-01", partial=False) -> str:
    """An alert inserted through ALERT(), which the marker router attributes."""
    root = _root(str(uuid.uuid4()), marker=marker, host=host, partial=partial)
    root.save()
    ALERT(root)
    return root.uuid


def _alert_row(alert_uuid: str) -> Alert:
    db = get_db()
    db.expire_all()
    return db.execute(select(Alert).where(Alert.uuid == alert_uuid)).unique().scalar_one()


def _events(run_uuid: str, kind: RunEventKind) -> list[dict]:
    db = get_db()
    db.expire_all()
    return [json.loads(event.details) for event in db.execute(
        select(SVSRunEvent).join(SVSRun, SVSRun.id == SVSRunEvent.run_id)
        .where(SVSRun.uuid == run_uuid, SVSRunEvent.kind == kind.value).order_by(SVSRunEvent.id)).scalars()]


def _close(run: SVSRun) -> None:
    """Cancels the run and lets the timers close it as its attribution window would. The window is
    still open by the wall clock, so the marker router keeps attributing to the closed run."""
    runs.cancel(run.uuid, LAUNCHER)
    result = runs.run_timers(now=run.attribution_ends_at + timedelta(seconds=1))
    assert result.closed == 1


def _set_owner(alert_uuid: str, username: str) -> None:
    db = get_db()
    user_id = db.execute(select(User.id).where(User.username == username)).scalar_one()
    db.execute(update(Alert).where(Alert.uuid == alert_uuid).values(owner_id=user_id))
    db.commit()


def _needs_attention(run_uuid: str) -> bool:
    db = get_db()
    db.expire_all()
    return db.execute(select(needs_attention_condition()).where(SVSRun.uuid == run_uuid)).scalar_one()


class TestClosingARun:
    def test_its_fully_attributed_alerts_become_simulated(self, run):
        by_marker = _alert(marker=run.marker)
        by_context = _alert()
        assert _alert_row(by_context).queue == get_config().svs.queue

        _close(run)

        automation_user_id = get_config().global_settings.automation_user_id
        for alert_uuid in (by_marker, by_context):
            alert = _alert_row(alert_uuid)
            assert alert.disposition == DISPOSITION_SIMULATED
            assert alert.disposition_user_id == automation_user_id
            assert get_db().execute(select(Comment.comment).where(Comment.uuid == alert_uuid)).scalar_one() == \
                f"closed with SVS test run {run.uuid}"

        (event,) = _events(run.uuid, RunEventKind.ALERTS_CLOSED)
        assert sorted(event["alerts"]) == sorted([by_marker, by_context])
        assert event == {**event, "disposition": DISPOSITION_SIMULATED, "late": False}
        assert not _needs_attention(run.uuid)

    def test_partial_taken_and_dispositioned_alerts_are_left_alone(self, run, caplog):
        partial = _alert(marker=run.marker, partial=True)
        taken = _alert(marker=run.marker)
        _set_owner(taken, "unittest")
        dispositioned = _alert(marker=run.marker)
        set_dispositions([dispositioned], DISPOSITION_FALSE_POSITIVE, get_config().global_settings.automation_user_id)
        mine = _alert(marker=run.marker)
        # the automation user owns what it dispositioned before; it counts as nobody
        _set_owner(mine, "ace")

        with caplog.at_level(logging.INFO):
            _close(run)

        assert _alert_row(partial).disposition == DISPOSITION_OPEN
        assert _alert_row(taken).disposition == DISPOSITION_OPEN
        assert _alert_row(dispositioned).disposition == DISPOSITION_FALSE_POSITIVE
        assert _alert_row(mine).disposition == DISPOSITION_SIMULATED
        (record,) = [r for r in caplog.records if getattr(r, "alert_uuids", None) is not None]
        assert record.alert_uuids == [mine]
        assert record.svs_run == run.uuid

        # the open ones keep the closed run in Needs attention
        assert _needs_attention(run.uuid)

    def test_an_alert_dispositioned_meanwhile_keeps_its_disposition(self, run, monkeypatch):
        """Closing chooses alerts, then dispositions them under the row lock; an analyst's
        disposition in between wins."""
        alert_uuid = _alert(marker=run.marker)
        chosen = runs._closable_alerts(SVSAttribution.run_id == run.id)

        def analyst_first(*conditions):
            set_dispositions([alert_uuid], DISPOSITION_FALSE_POSITIVE, get_config().global_settings.automation_user_id)
            return chosen

        monkeypatch.setattr(runs, "_closable_alerts", analyst_first)
        _close(run)
        assert _alert_row(alert_uuid).disposition == DISPOSITION_FALSE_POSITIVE
        assert _events(run.uuid, RunEventKind.ALERTS_CLOSED) == []

    def test_an_alert_disassociated_meanwhile_stays_open(self, run, monkeypatch):
        """Closing chooses the fully attributed alerts, then checks again under the row lock: an
        alert a person disassociated in between is not frozen without a run."""
        alert_uuid = _alert(marker=run.marker)
        chosen = runs._closable_alerts(SVSAttribution.run_id == run.id)
        user_id = get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()

        def disassociated_first(*conditions):
            # the timers' late-alert sweep chooses again after the close
            if not _events(run.uuid, RunEventKind.DISASSOCIATED):
                association.disassociate(run.uuid, alert_uuid, user_id, "unittest")
            return chosen

        monkeypatch.setattr(runs, "_closable_alerts", disassociated_first)
        _close(run)
        assert _alert_row(alert_uuid).disposition == DISPOSITION_OPEN
        assert _events(run.uuid, RunEventKind.ALERTS_CLOSED) == []

    def test_a_failure_never_undoes_the_close(self, run, monkeypatch):
        alert_uuid = _alert(marker=run.marker)
        monkeypatch.setattr("saq.error.reporting.write_error_report", lambda *a, **k: None)
        def down(*args, **kwargs):
            raise RuntimeError("database down")

        monkeypatch.setattr(runs, "set_dispositions", down)
        _close(run)

        assert get_db().execute(select(SVSRun.state).where(SVSRun.id == run.id)).scalar_one() == RunState.CLOSED
        assert _alert_row(alert_uuid).disposition == DISPOSITION_OPEN
        monkeypatch.undo()

        # the sweep closes it on the timers' next pass
        assert runs.run_timers().late_alerts_closed == 1
        assert _alert_row(alert_uuid).disposition == DISPOSITION_SIMULATED


class TestLateAlerts:
    def test_an_alert_attributed_after_the_run_closed_is_closed_by_the_sweep(self, run):
        _close(run)
        alert_uuid = _alert(marker=run.marker)
        assert _alert_row(alert_uuid).queue == get_config().svs.queue
        assert _needs_attention(run.uuid)

        assert runs.run_timers().late_alerts_closed == 1

        assert _alert_row(alert_uuid).disposition == DISPOSITION_SIMULATED
        (event,) = _events(run.uuid, RunEventKind.ALERTS_CLOSED)
        assert event["alerts"] == [alert_uuid] and event["late"] is True
        assert not _needs_attention(run.uuid)
        # nothing left to do
        assert runs.run_timers().late_alerts_closed == 0

    def test_the_sweep_leaves_open_runs_and_partial_alerts_alone(self, run):
        _alert(marker=run.marker)
        assert runs.run_timers().late_alerts_closed == 0

        _close(run)
        partial = _alert(marker=run.marker, partial=True)
        assert runs.run_timers().late_alerts_closed == 0
        assert _alert_row(partial).disposition == DISPOSITION_OPEN


class TestEventLog:
    def test_attributions_are_events_of_their_run(self, run):
        alert_uuid = _alert(marker=run.marker)

        (event,) = _events(run.uuid, RunEventKind.ATTRIBUTED)
        assert event["alert_uuid"] == alert_uuid
        (detection,) = event["detections"]
        assert detection == {**detection, "confidence": "marker", "late": False, "scan_point": "root_details"}
        assert len(detection["detection"]) == 64

    def test_a_removed_attribution_is_an_event(self, run):
        alert_uuid = _alert(marker=run.marker)

        # a later evaluation of the alert no longer finds the marker or the run's host
        root = _root(alert_uuid, host="srv-01")
        write_attributions(alert_uuid, evaluate(root, datetime.now()))

        (event,) = _events(run.uuid, RunEventKind.ATTRIBUTION_REMOVED)
        assert event["alert_uuid"] == alert_uuid
        assert len(event["detections"]) == 1

    def test_nothing_is_written_when_nothing_changed(self, run):
        alert_uuid = _alert(marker=run.marker)
        # judged by the event time it was first judged by: a different one would move it
        event_time = get_db().execute(select(SVSAttribution.event_time)
                                      .where(SVSAttribution.alert_uuid == alert_uuid)).scalars().first()
        write_attributions(alert_uuid, evaluate(_root(alert_uuid, marker=run.marker), event_time))
        assert len(_events(run.uuid, RunEventKind.ATTRIBUTED)) == 1


class TestResultInputs:
    def test_an_attribution_carries_its_detections_signature_and_marks_the_result_stale(self, run):
        root = _root(str(uuid.uuid4()), marker=run.marker)
        root.add_detection_point("yara hit", signature_uuid=YARA_RULE)
        root.save()
        ALERT(root)

        db = get_db()
        db.expire_all()
        signatures = set(db.execute(select(SVSAttribution.signature_uuid, SVSAttribution.signature_family)
                                    .where(SVSAttribution.alert_uuid == root.uuid)).all())
        assert signatures == {(GENERIC.uuid, "builtin"), (YARA_RULE, None)}
        state = db.get(SVSRunResultState, run.id)
        assert (state.stale, state.generation) == (True, 1)


class TestChangedSinceReview:
    def _review(self, run: SVSRun) -> None:
        # review arrives later in phase 4; the state is set directly
        db = get_db()
        db.execute(update(SVSRun).where(SVSRun.id == run.id).values(state=RunState.REVIEWED.value))
        db.commit()

    def test_a_late_alert_after_review_flags_the_run(self, run, caplog):
        self._review(run)
        assert not _needs_attention(run.uuid)

        with caplog.at_level(logging.INFO):
            alert_uuid = _alert(marker=run.marker)

        db = get_db()
        db.expire_all()
        assert db.execute(select(SVSRun.changed_since_review).where(SVSRun.id == run.id)).scalar_one() is True
        assert _needs_attention(run.uuid)
        assert any(r.getMessage().startswith(f"svs run {run.uuid} changed since review")
                   and r.alert_uuid == alert_uuid for r in caplog.records)
        # a reviewed run's alerts are the review's to close, never the sweep's
        assert runs.run_timers().late_alerts_closed == 0
        assert _alert_row(alert_uuid).disposition == DISPOSITION_OPEN

    def test_attributions_to_runs_not_reviewed_flag_nothing(self, run):
        _alert(marker=run.marker)
        db = get_db()
        db.expire_all()
        assert db.execute(select(SVSRun.changed_since_review).where(SVSRun.id == run.id)).scalar_one() is False


def test_open_alerts_condition(run):
    alert_uuid = _alert(marker=run.marker)
    db = get_db()
    assert db.execute(select(open_alerts_condition()).where(SVSRun.id == run.id)).scalar_one()

    set_dispositions([alert_uuid], DISPOSITION_FALSE_POSITIVE, get_config().global_settings.automation_user_id)
    db.expire_all()
    assert not db.execute(select(open_alerts_condition()).where(SVSRun.id == run.id)).scalar_one()
