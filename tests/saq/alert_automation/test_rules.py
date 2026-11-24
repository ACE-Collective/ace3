"""What an alert automation rule does to the alerts its trigger finds (docs/ALERT_AUTOMATION.md):
the external_remediation_confirmed trigger, the disposition, remediate and comment actions, the
guards, the runs and the modes."""

import json
import logging

import pytest
from sqlalchemy import delete

from saq.alert_automation import rules
from saq.alert_automation.rules import AlertAutomationAction, ActionOutcome, ActionStatus, sweep_rule
from saq.alert_automation.runs import alert_states
from saq.configuration.config import get_config
from saq.configuration.schema import AlertAutomationTypeConfig
from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE, DISPOSITION_OPEN, DISPOSITION_SIMULATED, F_EMAIL_DELIVERY
from saq.database.model import ExternalRemediationCheck
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

    def run(self, context):
        if FailingAction.failures:
            FailingAction.failures -= 1
            raise RuntimeError("the remediation system is down")
        return ActionOutcome(ActionStatus.DONE, {"ran": True})


@pytest.fixture
def failing_action(monkeypatch):
    get_config().alert_automation.action_types.append(AlertAutomationTypeConfig(
        name="failing", python_module=__name__, python_class="FailingAction"))
    monkeypatch.setattr(FailingAction, "failures", 0)
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

    (record,) = logged_with(caplog, logging.ERROR, alert_uuid=alert_uuid,
                            observable=f"{F_EMAIL_DELIVERY}:{DELIVERY_ALICE}")
    assert record.rule == RULE
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
