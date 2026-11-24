"""What an alert automation rule does to the alerts its trigger finds (docs/ALERT_AUTOMATION.md):
the external_remediation_confirmed trigger, the disposition, remediate and comment actions, the
guards, the runs and the modes."""

import json
import logging

import pytest
from sqlalchemy import delete, func, text, update

from saq.alert_automation import rules
from saq.alert_automation.rules import AlertAutomationAction, ActionOutcome, ActionStatus, sweep_rule
from saq.alert_automation.runs import alert_states, pending_runs, take_run
from saq.configuration.config import get_config
from saq.configuration.schema import AlertAutomationTypeConfig
from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE, DISPOSITION_OPEN, DISPOSITION_SIMULATED, F_EMAIL_DELIVERY
from saq.database.model import Alert, AlertAutomationRun, Comment, ExternalRemediationCheck
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction
from tests.saq.alert_automation.conftest import (
    ACTIONS,
    DELIVERY_ALICE,
    DELIVERY_BOB,
    OTHER_MESSAGE,
    PROBE,
    RULE,
    analyst_id,
    comments,
    confirm,
    make_alert,
    make_root,
    make_rule,
    removals,
    runs,
    set_alert,
    sweep,
)
from tests.saq.helpers import alert_row, logged_with, make_simulated, the_error_with_traceback

pytestmark = pytest.mark.integration


def _automation() -> int:
    return get_config().global_settings.automation_user_id


def _actions(run) -> list[dict]:
    return json.loads(run.actions)


@pytest.mark.usefixtures("remediable")
def test_confirmed_removal_dispositions_the_alert_and_removes_every_delivery_of_the_message(caplog):
    caplog.set_level(logging.INFO)
    alert_uuid = make_alert(DELIVERY_ALICE, DELIVERY_BOB, OTHER_MESSAGE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=ACTIONS + [{"type": "comment", "comment": "rule {rule} acted on {alert_uuid}"}])

    sweep(rule)

    alert = alert_row(alert_uuid)
    assert alert.disposition == DISPOSITION_DELIVERY
    assert alert.disposition_user_id == _automation()
    assert alert.owner_id == _automation()
    # every delivery of the confirmed message, and only those, queued as the automation user
    assert removals() == {DELIVERY_ALICE: _automation(), DELIVERY_BOB: _automation()}
    (disposition_comment, rule_comment) = comments(alert_uuid)
    assert disposition_comment[0] == _automation()
    assert disposition_comment[1].startswith(f"{PROBE} confirmed removal of {DELIVERY_ALICE} at ")
    assert disposition_comment[1].endswith("; ACE removal queued as a backstop")
    assert rule_comment == (_automation(), f"rule {RULE} acted on {alert_uuid}")

    (run,) = runs(alert_uuid)
    assert (run.rule_name, run.mode, run.status) == (RULE, "enforce", "done")
    assert [c["observable_value"] for c in json.loads(run.evidence)["confirmations"]] == [DELIVERY_ALICE]
    assert [(a["type"], a["status"], a["attempts"]) for a in _actions(run)] == [
        ("disposition", "done", 1), ("remediate", "done", 1), ("comment", "done", 1)]
    assert sorted(_actions(run)[1]["detail"]["queued"]) == [
        f"test:{F_EMAIL_DELIVERY}:{DELIVERY_ALICE}", f"test:{F_EMAIL_DELIVERY}:{DELIVERY_BOB}"]

    for action in ("disposition", "remediate", "comment"):
        assert logged_with(caplog, logging.INFO, alert_uuid=alert_uuid, rule=RULE, action=action, mode="enforce")


@pytest.mark.usefixtures("remediable")
def test_targets_evidence_removes_only_the_confirmed_delivery():
    alert_uuid = make_alert(DELIVERY_ALICE, DELIVERY_BOB)
    confirm(alert_uuid, DELIVERY_ALICE)

    sweep(make_rule(actions=[ACTIONS[0], {"type": "remediate", "targets": "evidence"}]))

    assert removals() == {DELIVERY_ALICE: _automation()}


# the disposition action checks the guards again under the row lock, so a rule without one, and a
# dry run, which never takes the lock, are each left to the sweep's guards alone
GUARDED_RULES = [("enforce", ACTIONS), ("dry_run", ACTIONS), ("enforce", [ACTIONS[1]])]


@pytest.mark.usefixtures("remediable")
@pytest.mark.parametrize("mode, actions", GUARDED_RULES)
def test_an_owned_alert_is_left_alone_until_it_is_unassigned(mode, actions):
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    set_alert(alert_uuid, owner_id=analyst_id())
    rule = make_rule(mode=mode, actions=actions)

    sweep(rule)

    assert alert_row(alert_uuid).disposition == DISPOSITION_OPEN
    assert removals() == {}
    assert runs(alert_uuid) == []

    set_alert(alert_uuid, owner_id=None)
    sweep(rule)

    assert [run.status for run in runs(alert_uuid)] == ["done"]


@pytest.mark.usefixtures("remediable")
def test_an_alert_the_automation_user_owns_is_acted_on():
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    set_alert(alert_uuid, owner_id=_automation())

    sweep(make_rule())

    assert alert_row(alert_uuid).disposition == DISPOSITION_DELIVERY


def _taken(alert_uuid):
    set_alert(alert_uuid, owner_id=analyst_id())


def _dispositioned(alert_uuid):
    set_alert(alert_uuid, disposition=DISPOSITION_FALSE_POSITIVE, disposition_user_id=analyst_id())


def _no_longer_confirmed(alert_uuid):
    db = get_db()
    db.execute(delete(ExternalRemediationCheck).where(ExternalRemediationCheck.alert_uuid == alert_uuid))
    db.commit()


@pytest.mark.usefixtures("remediable")
@pytest.mark.parametrize("change", [_taken, _dispositioned, _no_longer_confirmed])
def test_an_alert_that_changes_during_the_sweep_stops_the_rule(monkeypatch, caplog, change):
    caplog.set_level(logging.INFO)
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    opened = alert_row(alert_uuid).disposition

    def read_then_changed(alert_uuids):
        # the sweep reads the alert as it was, and it changes before the disposition locks its row
        states = alert_states(alert_uuids)
        change(alert_uuid)
        return states

    monkeypatch.setattr(rules, "alert_states", read_then_changed)
    sweep(make_rule())

    assert opened == DISPOSITION_OPEN
    assert alert_row(alert_uuid).disposition == (DISPOSITION_FALSE_POSITIVE if change is _dispositioned
                                                 else DISPOSITION_OPEN)
    assert alert_row(alert_uuid).disposition_user_id != _automation()
    assert removals() == {}
    assert comments(alert_uuid) == []
    # nothing was done, so no run holds the alert back once it is OPEN and unowned again
    assert runs(alert_uuid) == []
    assert logged_with(caplog, logging.INFO, alert_uuid=alert_uuid, action="disposition", rule=RULE)


@pytest.mark.usefixtures("remediable")
def test_an_alert_whose_run_cannot_be_recorded_is_logged_and_the_sweep_goes_on(monkeypatch, caplog):
    failing_uuid = make_alert(DELIVERY_ALICE)
    confirm(failing_uuid, DELIVERY_ALICE)
    other_uuid = make_alert(OTHER_MESSAGE)
    confirm(other_uuid, OTHER_MESSAGE)
    real_claim = rules.claim_run

    def claim(rule_name, alert_uuid, *args):
        if alert_uuid == failing_uuid:
            raise RuntimeError("lost the database")
        return real_claim(rule_name, alert_uuid, *args)

    monkeypatch.setattr(rules, "claim_run", claim)
    sweep(make_rule())

    the_error_with_traceback(caplog, alert_uuid=failing_uuid, rule=RULE)
    assert alert_row(failing_uuid).disposition == DISPOSITION_OPEN
    assert alert_row(other_uuid).disposition == DISPOSITION_DELIVERY


@pytest.mark.usefixtures("remediable")
@pytest.mark.parametrize("mode, actions", GUARDED_RULES)
@pytest.mark.parametrize("disposition", [DISPOSITION_FALSE_POSITIVE, DISPOSITION_SIMULATED])
def test_an_alert_that_is_not_open_is_left_alone(disposition, mode, actions):
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    if disposition == DISPOSITION_SIMULATED:
        make_simulated(alert_row(alert_uuid))
        # SVS leaves the alert to the automation user, whom the ownership guard lets through
        assert alert_row(alert_uuid).owner_id == _automation()
    else:
        set_alert(alert_uuid, disposition=disposition)

    sweep(make_rule(mode=mode, actions=actions))

    assert alert_row(alert_uuid).disposition == disposition
    assert removals() == {}
    assert runs(alert_uuid) == []


@pytest.mark.usefixtures("remediable")
def test_dry_run_records_the_decision_and_changes_nothing_then_enforce_acts():
    alert_uuid = make_alert(DELIVERY_ALICE, DELIVERY_BOB)
    confirm(alert_uuid, DELIVERY_ALICE)

    sweep(make_rule(mode="dry_run"))

    alert = alert_row(alert_uuid)
    assert (alert.disposition, alert.owner_id) == (DISPOSITION_OPEN, None)
    assert removals() == {}
    assert comments(alert_uuid) == []
    (dry,) = runs(alert_uuid)
    assert (dry.mode, dry.status) == ("dry_run", "done")
    disposition, remediate = _actions(dry)
    assert disposition["detail"]["disposition"] == DISPOSITION_DELIVERY
    assert disposition["detail"]["comment"].startswith(f"{PROBE} confirmed removal of {DELIVERY_ALICE} at ")
    assert sorted(remediate["detail"]["queued"]) == [
        f"test:{F_EMAIL_DELIVERY}:{DELIVERY_ALICE}", f"test:{F_EMAIL_DELIVERY}:{DELIVERY_BOB}"]

    sweep(make_rule(mode="enforce"))

    assert alert_row(alert_uuid).disposition == DISPOSITION_DELIVERY
    assert removals() == {DELIVERY_ALICE: _automation(), DELIVERY_BOB: _automation()}
    assert [(run.mode, run.status) for run in runs(alert_uuid)] == [("dry_run", "done"), ("enforce", "done")]


@pytest.mark.usefixtures("remediable")
def test_a_target_whose_removal_is_under_way_is_not_queued_again():
    alert_uuid = make_alert(DELIVERY_ALICE, DELIVERY_BOB)
    confirm(alert_uuid, DELIVERY_ALICE)
    RemediationTarget("test", F_EMAIL_DELIVERY, DELIVERY_BOB).queue_remediation(RemediationAction.REMOVE, analyst_id())

    sweep(make_rule())

    assert removals() == {DELIVERY_ALICE: _automation(), DELIVERY_BOB: analyst_id()}
    (run,) = runs(alert_uuid)
    assert _actions(run)[1]["detail"]["covered"] == [f"test:{F_EMAIL_DELIVERY}:{DELIVERY_BOB}"]


@pytest.mark.usefixtures("remediable")
def test_a_confirmation_older_than_max_age_hours_does_not_fire():
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE, hours_ago=121)
    other_uuid = make_alert(OTHER_MESSAGE)
    confirm(other_uuid, OTHER_MESSAGE, hours_ago=119)

    sweep(make_rule(max_age_hours=120))

    assert alert_row(alert_uuid).disposition == DISPOSITION_OPEN
    assert runs(alert_uuid) == []
    assert alert_row(other_uuid).disposition == DISPOSITION_DELIVERY


@pytest.mark.usefixtures("remediable")
def test_another_probes_confirmation_does_not_fire():
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE, probe_name="another_probe")

    sweep(make_rule())

    assert runs(alert_uuid) == []


@pytest.mark.usefixtures("remediable")
def test_a_check_row_with_no_alert_row_fires_once_the_alert_exists():
    root = make_root(DELIVERY_ALICE)
    confirm(root.uuid, DELIVERY_ALICE)
    rule = make_rule()

    sweep(rule)

    assert runs(root.uuid) == []
    assert removals() == {}

    ALERT(root)
    sweep(rule)

    assert alert_row(root.uuid).disposition == DISPOSITION_DELIVERY
    assert removals() == {DELIVERY_ALICE: _automation()}


class FailingAction(AlertAutomationAction):
    """An action type an integration could register; it fails as often as the test says."""
    failures = 0
    calls = 0

    def run(self, context):
        FailingAction.calls += 1
        if FailingAction.failures:
            FailingAction.failures -= 1
            raise RuntimeError("the remediation system is down")
        return ActionOutcome(ActionStatus.DONE, {"ran": True})


@pytest.fixture
def failing_action(monkeypatch):
    get_config().alert_automation.action_types.append(AlertAutomationTypeConfig(
        name="failing", python_module=__name__, python_class="FailingAction"))
    monkeypatch.setattr(FailingAction, "failures", 0)
    monkeypatch.setattr(FailingAction, "calls", 0)
    return FailingAction


@pytest.mark.usefixtures("remediable")
def test_a_failing_action_is_logged_and_retried_without_repeating_what_succeeded(failing_action, caplog):
    failing_action.failures = 1
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=[ACTIONS[0], {"type": "failing"}])

    sweep(rule)

    assert alert_row(alert_uuid).disposition == DISPOSITION_DELIVERY
    the_error_with_traceback(caplog, alert_uuid=alert_uuid, rule=RULE, action="failing", mode="enforce")
    (run,) = runs(alert_uuid)
    assert run.status == "pending"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 1), ("pending", 1)]

    # the alert is DELIVERY now, which the rule's own disposition set: the run goes on
    sweep(rule)

    (run,) = runs(alert_uuid)
    assert run.status == "done"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 1), ("done", 2)]
    # the disposition, and its comment, did not run again
    assert len(comments(alert_uuid)) == 1


@pytest.mark.usefixtures("remediable")
def test_an_action_that_keeps_failing_is_marked_failed(failing_action, caplog):
    failing_action.failures = 10
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=[{"type": "failing"}, {"type": "comment", "comment": "after"}])

    sweep(rule, max_attempts=2)
    sweep(rule, max_attempts=2)

    (run,) = runs(alert_uuid)
    assert run.status == "failed"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("failed", 2), ("pending", 0)]
    assert "RuntimeError: the remediation system is down" in _actions(run)[0]["reason"]
    gave_up = [r for r in logged_with(caplog, logging.ERROR, alert_uuid=alert_uuid, action="failing")
               if "gave up after 2 attempts" in r.getMessage()]
    assert len(gave_up) == 1

    sweep(rule, max_attempts=2)

    assert failing_action.failures == 8
    assert comments(alert_uuid) == []


def test_an_observable_with_no_remediation_target_is_logged_at_error(caplog):
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)

    sweep(make_rule())

    record = the_error_with_traceback(caplog, alert_uuid=alert_uuid, observable=f"{F_EMAIL_DELIVERY}:{DELIVERY_ALICE}")
    assert record.rule == RULE
    # the error report groups by the exception's text, which names the type and not the observable
    assert str(record.exc_info[1]) == f"no remediation target for {F_EMAIL_DELIVERY}"
    assert removals() == {}
    (run,) = runs(alert_uuid)
    assert _actions(run)[1]["detail"]["untargeted"] == [f"{F_EMAIL_DELIVERY}:{DELIVERY_ALICE}"]


@pytest.mark.usefixtures("remediable")
def test_an_alert_with_nothing_to_remediate_skips_the_action():
    alert_uuid = make_alert(OTHER_MESSAGE)
    # the confirmed delivery is not in the alert's tree
    confirm(alert_uuid, DELIVERY_ALICE)

    sweep(make_rule())

    (run,) = runs(alert_uuid)
    assert run.status == "done"
    assert _actions(run)[1]["status"] == "skipped"
    assert removals() == {}


@pytest.mark.usefixtures("remediable")
def test_a_rule_acts_once_even_after_the_alert_is_reopened():
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule()
    sweep(rule)
    first = removals()

    sweep(rule)
    set_alert(alert_uuid, disposition=DISPOSITION_OPEN, owner_id=None)
    sweep(rule)

    assert alert_row(alert_uuid).disposition == DISPOSITION_OPEN
    assert removals() == first
    assert len(comments(alert_uuid)) == 1
    (run,) = runs(alert_uuid)
    assert [a["attempts"] for a in _actions(run)] == [1, 1]


@pytest.mark.usefixtures("remediable")
def test_an_overlapping_sweep_does_not_act_on_an_alert_that_already_has_a_run():
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule()
    (candidate,) = rule.trigger.candidates(None, 10)
    sweep(rule)
    set_alert(alert_uuid, disposition=DISPOSITION_OPEN, owner_id=None)

    # a second instance that chose the alert before the first recorded its run
    rules.process_alert(rule, alert_uuid, candidate.evidence, alert_states([alert_uuid])[alert_uuid], None, 5)

    assert alert_row(alert_uuid).disposition == DISPOSITION_OPEN
    assert len(comments(alert_uuid)) == 1
    (run,) = runs(alert_uuid)
    assert [a["attempts"] for a in _actions(run)] == [1, 1]


@pytest.mark.usefixtures("remediable")
def test_the_sweep_pages_through_every_candidate():
    alert_uuids = [make_alert(f"<page-{index}@example.com>|alice@example.com") for index in range(5)]
    for index, alert_uuid in enumerate(alert_uuids):
        confirm(alert_uuid, f"<page-{index}@example.com>|alice@example.com")

    sweep_rule(make_rule(), batch_size=2, max_attempts=5)

    assert {alert_row(alert_uuid).disposition for alert_uuid in alert_uuids} == {DISPOSITION_DELIVERY}


def _expire_lease(alert_uuid):
    """As though the lease of the sweep that had the alert's run ran out."""
    db = get_db()
    db.execute(update(AlertAutomationRun).where(AlertAutomationRun.alert_uuid == alert_uuid).values(
        lease_expires=func.DATE_SUB(func.NOW(), text("INTERVAL 1 SECOND"))))
    db.commit()


class Killed(BaseException):
    """What the sweep sees of the process dying: nothing catches it."""


@pytest.mark.usefixtures("remediable")
def test_a_sweep_that_dies_after_the_disposition_leaves_the_removal_to_a_later_sweep(monkeypatch):
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule()

    def killed(self, context):
        raise Killed()

    with monkeypatch.context() as patched:
        patched.setattr(type(rule.actions[1]), "run", killed)
        with pytest.raises(Killed):
            sweep(rule)

    assert alert_row(alert_uuid).disposition == DISPOSITION_DELIVERY
    (run,) = runs(alert_uuid)
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 1), ("pending", 0)]

    # the dead sweep's claim holds the run until its lease runs out
    sweep(rule)
    assert removals() == {}

    _expire_lease(alert_uuid)
    sweep(rule)

    assert removals() == {DELIVERY_ALICE: _automation()}
    (run,) = runs(alert_uuid)
    assert run.status == "done"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 1), ("done", 1)]
    assert len(comments(alert_uuid)) == 1


class BadWriteAction(AlertAutomationAction):
    """Fails in a get_db() write on the alerts the test names, and does nothing on the others."""
    alert_uuids: set = set()

    def run(self, context):
        if context.alert_uuid in BadWriteAction.alert_uuids:
            get_db().add(Comment(user_id=None, uuid=context.alert_uuid, comment="never written"))
            get_db().commit()
        return ActionOutcome(ActionStatus.DONE)


def test_a_failed_write_on_one_alert_does_not_fail_the_next_alert(monkeypatch, caplog):
    get_config().alert_automation.action_types.append(AlertAutomationTypeConfig(
        name="bad_write", python_module=__name__, python_class="BadWriteAction"))
    first_uuid, second_uuid = sorted(make_alert(DELIVERY_ALICE) for _ in range(2))
    for alert_uuid in (first_uuid, second_uuid):
        confirm(alert_uuid, DELIVERY_ALICE)
    monkeypatch.setattr(BadWriteAction, "alert_uuids", {first_uuid})

    sweep(make_rule(actions=[{"type": "bad_write"}, {"type": "comment", "comment": "after"}]))

    the_error_with_traceback(caplog, alert_uuid=first_uuid, action="bad_write")
    assert logged_with(caplog, logging.ERROR, alert_uuid=second_uuid) == []
    assert comments(second_uuid) == [(_automation(), "after")]
    assert [run.status for run in runs(second_uuid)] == ["done"]


@pytest.mark.usefixtures("remediable")
def test_a_sweep_that_read_a_pending_run_another_sweep_finished_leaves_it_alone(failing_action, caplog):
    failing_action.failures = 1
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=[{"type": "failing"}, {"type": "comment", "comment": "once"}])
    sweep(rule)
    # a second instance reads the pending run, and the first retries it to the end before it acts
    (stale,) = pending_runs(RULE, "enforce", 0, 10)
    sweep(rule)

    caplog.clear()

    rules.process_alert(rule, alert_uuid, stale.evidence, alert_states([alert_uuid])[alert_uuid], stale, 5)

    # the failure, then the other sweep's retry: the stale sweep ran nothing
    assert failing_action.calls == 2
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    assert comments(alert_uuid) == [(_automation(), "once")]
    (run,) = runs(alert_uuid)
    assert run.status == "done"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 2), ("done", 1)]


@pytest.mark.usefixtures("remediable")
def test_a_run_another_sweep_has_claimed_is_not_retried_until_its_lease_runs_out(failing_action):
    failing_action.failures = 1
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=[{"type": "failing"}, {"type": "comment", "comment": "once"}])
    sweep(rule)
    (other,) = pending_runs(RULE, "enforce", 0, 10)
    assert take_run(other)

    sweep(rule)

    assert comments(alert_uuid) == []
    assert [run.status for run in runs(alert_uuid)] == ["pending"]

    _expire_lease(alert_uuid)
    sweep(rule)

    assert comments(alert_uuid) == [(_automation(), "once")]
    assert [run.status for run in runs(alert_uuid)] == ["done"]


class HookAction(AlertAutomationAction):
    """Runs the test's hook on the alert, and returns what it returns, or is done."""
    hook = None

    def run(self, context):
        return HookAction.hook(context.alert_uuid) or ActionOutcome(ActionStatus.DONE)


@pytest.fixture
def hook_action(monkeypatch):
    get_config().alert_automation.action_types.append(AlertAutomationTypeConfig(
        name="hook", python_module=__name__, python_class="HookAction"))
    return HookAction


@pytest.mark.usefixtures("remediable")
def test_a_sweep_whose_run_another_sweep_took_over_logs_it_and_stops(hook_action, monkeypatch, caplog):
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)

    def taken_over(alert_uuid):
        # the action outlasts the sweep's lease, and another sweep claims the run
        _expire_lease(alert_uuid)
        (other,) = pending_runs(RULE, "enforce", 0, 10)
        assert take_run(other)

    monkeypatch.setattr(hook_action, "hook", taken_over)
    sweep(make_rule(actions=[{"type": "hook"}, {"type": "comment", "comment": "after"}]))

    record = the_error_with_traceback(caplog, alert_uuid=alert_uuid, rule=RULE)
    assert "another sweep claimed the run" in record.getMessage()
    assert comments(alert_uuid) == []
    (run,) = runs(alert_uuid)
    # what the other sweep claimed is left as it was
    assert run.status == "pending"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("pending", 0), ("pending", 0)]


@pytest.mark.usefixtures("remediable")
def test_a_sweep_that_read_a_pending_run_another_sweep_advanced_leaves_it_alone(hook_action, failing_action,
                                                                                 monkeypatch, caplog):
    calls = []

    def fails_once(alert_uuid):
        calls.append(alert_uuid)
        if len(calls) == 1:
            raise RuntimeError("the comment system is down")

    monkeypatch.setattr(hook_action, "hook", fails_once)
    failing_action.failures = 10
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=[{"type": "hook"}, {"type": "failing"}])
    sweep(rule)
    # a second instance reads the pending run, and the first retries it: the hook is done, the
    # failing action fails again, and the run is pending and unclaimed as it was when it was read
    (stale,) = pending_runs(RULE, "enforce", 0, 10)
    sweep(rule)
    caplog.clear()

    rules.process_alert(rule, alert_uuid, stale.evidence, alert_states([alert_uuid])[alert_uuid], stale, 5)

    assert len(calls) == 2
    assert failing_action.calls == 1
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    (run,) = runs(alert_uuid)
    assert run.status == "pending"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 2), ("pending", 1)]


@pytest.mark.usefixtures("remediable")
def test_a_sweep_whose_unstarted_run_another_sweep_took_over_keeps_it_when_its_action_defers(hook_action,
                                                                                              monkeypatch, caplog):
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)

    def taken_over_then_defers(alert_uuid):
        _expire_lease(alert_uuid)
        (other,) = pending_runs(RULE, "enforce", 0, 10)
        assert take_run(other)
        return ActionOutcome(ActionStatus.DEFERRED, reason="not yet")

    monkeypatch.setattr(hook_action, "hook", taken_over_then_defers)
    sweep(make_rule(actions=[{"type": "hook"}, {"type": "comment", "comment": "after"}]))

    record = the_error_with_traceback(caplog, alert_uuid=alert_uuid, rule=RULE)
    assert "so it was not deleted" in record.getMessage()
    # the other sweep's run is kept, not deleted under it
    (run,) = runs(alert_uuid)
    assert run.status == "pending"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("pending", 0), ("pending", 0)]
    assert comments(alert_uuid) == []


@pytest.mark.usefixtures("remediable")
@pytest.mark.parametrize("before, after", [
    ([{"type": "failing"}], [{"type": "failing"}, {"type": "comment", "comment": "added"}]),
    ([{"type": "failing"}, {"type": "comment", "comment": "kept"}], [{"type": "comment", "comment": "kept"}]),
])
def test_a_pending_run_of_a_rule_whose_actions_changed_is_marked_failed(failing_action, caplog, before, after):
    failing_action.failures = 1
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    sweep(make_rule(actions=before))
    caplog.clear()

    sweep(make_rule(actions=after))

    record = the_error_with_traceback(caplog, alert_uuid=alert_uuid, rule=RULE)
    assert "was started for" in record.getMessage()
    assert comments(alert_uuid) == []
    (run,) = runs(alert_uuid)
    assert run.status == "failed"
    assert [(a["type"], a["status"], a["attempts"]) for a in _actions(run)] == [
        (step["type"], "pending", 1 if step["type"] == "failing" else 0) for step in before]


def test_a_dry_run_comment_is_recorded_and_not_added():
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)

    sweep(make_rule(mode="dry_run", actions=[{"type": "comment", "comment": "rule {rule} acted"}]))

    assert comments(alert_uuid) == []
    (run,) = runs(alert_uuid)
    assert (run.status, _actions(run)[0]["detail"]) == ("done", {"comment": f"rule {RULE} acted"})


@pytest.mark.usefixtures("remediable")
def test_a_started_run_stops_while_an_analyst_has_the_alert(failing_action, caplog):
    caplog.set_level(logging.INFO)
    failing_action.failures = 1
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=[ACTIONS[0], {"type": "failing"}])
    sweep(rule)
    set_alert(alert_uuid, owner_id=analyst_id())

    sweep(rule)

    (run,) = runs(alert_uuid)
    assert run.status == "pending"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 1), ("pending", 1)]
    assert logged_with(caplog, logging.INFO, alert_uuid=alert_uuid, reason=f"user {analyst_id()} owns the alert")

    set_alert(alert_uuid, owner_id=None)
    sweep(rule)

    (run,) = runs(alert_uuid)
    assert run.status == "done"


def test_a_started_run_whose_disposition_defers_is_kept(monkeypatch):
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)

    def read_then_taken(alert_uuids):
        states = alert_states(alert_uuids)
        _taken(alert_uuid)
        return states

    monkeypatch.setattr(rules, "alert_states", read_then_taken)
    sweep(make_rule(actions=[{"type": "comment", "comment": "first"}, ACTIONS[0]]))

    assert alert_row(alert_uuid).disposition == DISPOSITION_OPEN
    assert comments(alert_uuid) == [(_automation(), "first")]
    # the comment was added, so the run is kept and the comment is not added again
    (run,) = runs(alert_uuid)
    assert run.status == "pending"
    assert [(a["status"], a["attempts"]) for a in _actions(run)] == [("done", 1), ("pending", 0)]


@pytest.mark.usefixtures("remediable")
def test_a_pending_run_whose_alert_was_deleted_is_left_as_it_is(failing_action, caplog):
    caplog.set_level(logging.INFO)
    failing_action.failures = 1
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)
    rule = make_rule(actions=[ACTIONS[0], {"type": "failing"}])
    sweep(rule)
    (before,) = runs(alert_uuid)
    actions_before = _actions(before)
    db = get_db()
    db.execute(delete(Alert).where(Alert.uuid == alert_uuid))
    db.commit()
    caplog.clear()

    sweep(rule)

    (run,) = runs(alert_uuid)
    assert (run.status, _actions(run)) == ("pending", actions_before)
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    assert logged_with(caplog, logging.INFO, alert_uuid=alert_uuid, reason="the alert does not exist")


@pytest.mark.usefixtures("remediable")
def test_a_sweep_stops_between_alerts_when_it_is_stopping(monkeypatch):
    alert_uuids = [make_alert(f"<stop-{index}@example.com>|alice@example.com") for index in range(2)]
    for index, alert_uuid in enumerate(alert_uuids):
        confirm(alert_uuid, f"<stop-{index}@example.com>|alice@example.com")
    processed = []
    real_process_alert = rules.process_alert

    def process_alert(rule, alert_uuid, *args):
        processed.append(alert_uuid)
        real_process_alert(rule, alert_uuid, *args)

    monkeypatch.setattr(rules, "process_alert", process_alert)
    # the sweep is told to stop once it has acted on an alert
    sweep_rule(make_rule(), batch_size=100, max_attempts=5, stopping=lambda: bool(processed))

    (first,) = processed
    (second,) = set(alert_uuids) - {first}
    assert alert_row(first).disposition == DISPOSITION_DELIVERY
    assert alert_row(second).disposition == DISPOSITION_OPEN
    assert runs(second) == []
