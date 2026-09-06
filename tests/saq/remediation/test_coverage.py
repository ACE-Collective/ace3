"""Tests for the per-alert remediation coverage used by the alert list badge."""
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from saq.constants import F_EMAIL_DELIVERY, create_email_delivery
from saq.database.database_observable import upsert_observable
from saq.database.model import ExternalRemediationCheck, ObservableRemediationMapping, Remediation
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.environment import get_global_runtime_settings
from saq.observables.generator import create_observable
from saq.remediation.coverage import (
    ACE_SOURCE,
    TOOLTIP_TARGET_LIMIT,
    CoverageState,
    RemediationCoverage,
    TargetCoverage,
    assemble_coverage,
    get_remediation_coverage,
)
from saq.remediation.external.database import ace_supersede_reason, probe_supersede_reason
from saq.remediation.external.types import CheckResult, CheckStatus
from tests.saq.helpers import create_root_analysis

ALICE = create_email_delivery("<msg-1@example.com>", "alice@example.com")
BOB = create_email_delivery("<msg-1@example.com>", "bob@example.com")
CAROL = create_email_delivery("<msg-1@example.com>", "carol@example.com")
ALERT_UUID = "alert-1"


def _ace_row(status="COMPLETED", result="SUCCESS", action="remove"):
    return SimpleNamespace(status=status, result=result, action=action)


def _event(source="Fake Source", target="alice@example.com"):
    return {
        "source": source,
        "event_type": "auto_remediated",
        "timestamp": "2026-05-13T12:00:00Z",
        "description": "Auto-Remediated",
        "target": target,
    }


def _check(value, status="COMPLETED", result=None, events=None, probe_name="fake_probe", result_message=None):
    return SimpleNamespace(
        id=1,
        observable_value=value,
        status=status,
        result=result,
        probe_name=probe_name,
        result_message=result_message,
        events_json=json.dumps(events) if events is not None else None,
    )


def _assemble(targets=(ALICE, BOB), ace=None, checks=None):
    return assemble_coverage(
        [ALERT_UUID],
        {ALERT_UUID: set(targets)},
        ace or {},
        {ALERT_UUID: checks or []},
    )[ALERT_UUID]


@pytest.mark.unit
def test_no_targets_is_not_visible():
    coverage = _assemble(targets=())
    assert coverage.state is CoverageState.NONE
    assert not coverage.visible


@pytest.mark.unit
def test_targets_without_any_activity_are_not_visible():
    coverage = _assemble()
    assert coverage.total == 2
    assert coverage.state is CoverageState.NONE
    assert not coverage.visible


@pytest.mark.unit
def test_ace_success_on_every_target_is_remediated():
    coverage = _assemble(ace={ALICE: [_ace_row()], BOB: [_ace_row()]})
    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.sources == [ACE_SOURCE]
    assert coverage.label == "remediated 2/2 · ACE"
    assert coverage.css_class == "text-bg-success"


@pytest.mark.unit
def test_only_the_latest_ace_row_counts():
    # remove succeeded, then a restore succeeded: the message is back in the mailbox
    rows = [_ace_row(), _ace_row(action="restore")]
    coverage = _assemble(targets=(ALICE,), ace={ALICE: rows})
    assert coverage.state is CoverageState.UNREMEDIATED
    assert coverage.label == "not remediated 0/1"

    # and the other way around: a failed remove followed by a successful one
    rows = [_ace_row(result="FAILED"), _ace_row()]
    coverage = _assemble(targets=(ALICE,), ace={ALICE: rows})
    assert coverage.state is CoverageState.REMEDIATED


@pytest.mark.unit
def test_confirmed_probe_on_one_target_is_partial():
    checks = [
        _check(ALICE, result=CheckResult.CONFIRMED.value, events=[_event()]),
        _check(BOB, status=CheckStatus.NEW.value),
    ]
    coverage = _assemble(checks=checks)
    assert coverage.state is CoverageState.PARTIAL
    assert coverage.label == "remediated 1/2 · Fake Source"
    assert coverage.css_class == "text-bg-warning"
    assert coverage.tooltip == "alice@example.com: Fake Source\nbob@example.com: watching"


@pytest.mark.unit
def test_confirmed_probe_without_events_falls_back_to_probe_name():
    coverage = _assemble(targets=(ALICE,), checks=[_check(ALICE, result=CheckResult.CONFIRMED.value)])
    assert coverage.sources == ["fake_probe"]


@pytest.mark.unit
def test_ace_failure_is_failed_unless_another_source_confirmed():
    coverage = _assemble(ace={ALICE: [_ace_row(result="FAILED")], BOB: [_ace_row()]})
    assert coverage.state is CoverageState.FAILED
    assert coverage.label == "remediation failed 1/2 · ACE"
    assert coverage.css_class == "text-bg-danger"

    # a vendor confirmed the target ACE could not remove: it is gone either way
    checks = [_check(ALICE, result=CheckResult.CONFIRMED.value, events=[_event()])]
    coverage = _assemble(ace={ALICE: [_ace_row(result="FAILED")], BOB: [_ace_row()]}, checks=checks)
    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.sources == [ACE_SOURCE, "Fake Source"]


@pytest.mark.unit
def test_ace_not_found_is_not_in_mailbox_rather_than_failed():
    # something else already removed the email (or it was never delivered): ACE
    # found nothing to remove, which is neither a remediation nor a failure
    coverage = _assemble(targets=(ALICE,), ace={ALICE: [_ace_row(result="NOT_FOUND")]})
    assert coverage.state is CoverageState.NOT_FOUND
    assert coverage.label == "not in mailbox 1/1"
    assert coverage.cell_css_class == "table-light"
    assert coverage.tooltip == "alice@example.com: not in mailbox"

    # it outranks a probe that is still watching the same message
    coverage = _assemble(
        targets=(ALICE,),
        ace={ALICE: [_ace_row(result="NOT_FOUND")]},
        checks=[_check(ALICE, status=CheckStatus.NEW.value)],
    )
    assert coverage.state is CoverageState.NOT_FOUND

    # a vendor confirmation for the same message wins outright
    checks = [_check(ALICE, result=CheckResult.CONFIRMED.value, events=[_event()])]
    coverage = _assemble(targets=(ALICE,), ace={ALICE: [_ace_row(result="NOT_FOUND")]}, checks=checks)
    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.sources == ["Fake Source"]


@pytest.mark.unit
def test_not_in_mailbox_counts_as_covered_once_something_was_remediated():
    # two addresses for one mailbox: ACE's remove through one succeeded, the other
    # raced it and found nothing left. Nothing is outstanding, so the alert is
    # remediated, with the tooltip still honest about which target did the work.
    coverage = _assemble(ace={ALICE: [_ace_row(result="NOT_FOUND")], BOB: [_ace_row()]})
    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.label == "remediated 2/2 · ACE"
    assert coverage.tooltip == "alice@example.com: not in mailbox\nbob@example.com: ACE"

    # the same with a vendor doing the removing on the other target
    checks = [_check(BOB, result=CheckResult.CONFIRMED.value, events=[_event(target="bob@example.com")])]
    coverage = _assemble(ace={ALICE: [_ace_row(result="NOT_FOUND")]}, checks=checks)
    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.label == "remediated 2/2 · Fake Source"

    # one remediated, one not in the mailbox, one still being watched: partial, counting both covered
    targets = (ALICE, BOB, CAROL)
    coverage = _assemble(targets=targets, ace={ALICE: [_ace_row(result="NOT_FOUND")], BOB: [_ace_row()]},
                         checks=[_check(CAROL, status=CheckStatus.NEW.value)])
    assert coverage.state is CoverageState.PARTIAL
    assert coverage.label == "remediated 2/3 · ACE"

    # nothing remediated at all stays "not in mailbox", even alongside a watched target
    coverage = _assemble(ace={ALICE: [_ace_row(result="NOT_FOUND")]}, checks=[_check(BOB, status=CheckStatus.NEW.value)])
    assert coverage.state is CoverageState.NOT_FOUND
    assert coverage.label == "not in mailbox 1/2"


@pytest.mark.unit
def test_open_probes_with_nothing_confirmed_are_watching():
    checks = [
        _check(ALICE, status=CheckStatus.NEW.value),
        _check(BOB, status=CheckStatus.IN_PROGRESS.value),
    ]
    coverage = _assemble(checks=checks)
    assert coverage.state is CoverageState.PENDING
    assert coverage.label == "watching 0/2"
    assert coverage.tooltip == "alice@example.com: watching\nbob@example.com: watching"


@pytest.mark.unit
def test_ace_removal_in_flight_is_remediating():
    coverage = _assemble(
        ace={ALICE: [_ace_row(status="IN_PROGRESS", result=None)]},
        checks=[_check(BOB, status=CheckStatus.IN_PROGRESS.value)],
    )
    assert coverage.state is CoverageState.PENDING
    assert coverage.label == "remediating 0/2"
    assert coverage.tooltip == "alice@example.com: remediating\nbob@example.com: watching"

    # an in-flight restore is not a removal in progress
    coverage = _assemble(targets=(ALICE,), ace={ALICE: [_ace_row(status="NEW", result=None, action="restore")]})
    assert coverage.label == "watching 0/1"


@pytest.mark.unit
def test_probes_that_finished_without_confirming_are_unremediated():
    checks = [
        _check(ALICE, result=CheckResult.EXPIRED.value),
        _check(BOB, result=CheckResult.NOT_FOUND.value),
    ]
    coverage = _assemble(checks=checks)
    assert coverage.state is CoverageState.UNREMEDIATED
    assert coverage.label == "not remediated 0/2"
    assert coverage.tooltip == "alice@example.com: not remediated\nbob@example.com: not remediated"


@pytest.mark.unit
def test_superseded_rows_credit_whoever_confirmed_first():
    when = datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc)
    checks = [
        _check(ALICE, result=CheckResult.SUPERSEDED.value, result_message=probe_supersede_reason("other_probe", when)),
        _check(BOB, result=CheckResult.SUPERSEDED.value, result_message=ace_supersede_reason(7, when)),
    ]
    coverage = _assemble(checks=checks)
    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.sources == [ACE_SOURCE, "other_probe"]

    coverage = _assemble(targets=(ALICE,), checks=[_check(ALICE, result=CheckResult.SUPERSEDED.value, result_message="???")])
    assert coverage.sources == ["superseded"]


@pytest.mark.unit
def test_superseded_row_defers_to_the_visible_confirmation():
    # the sibling that confirmed first is on this same alert: its event label wins,
    # the probe name in the supersede reason must not show up as a second source
    when = datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc)
    checks = [
        _check(ALICE, probe_name="fake_probe", result=CheckResult.CONFIRMED.value, events=[_event()]),
        _check(ALICE, probe_name="other", result=CheckResult.SUPERSEDED.value,
               result_message=probe_supersede_reason("fake_probe", when)),
    ]
    coverage = _assemble(targets=(ALICE,), checks=checks)
    assert coverage.sources == ["Fake Source"]

    # likewise when ACE's own successful remove is what superseded the probe
    checks = [_check(ALICE, result=CheckResult.SUPERSEDED.value, result_message=ace_supersede_reason(7, when))]
    coverage = _assemble(targets=(ALICE,), ace={ALICE: [_ace_row()]}, checks=checks)
    assert coverage.sources == [ACE_SOURCE]


@pytest.mark.unit
def test_check_for_an_unmapped_target_adds_the_target():
    coverage = _assemble(targets=(ALICE,), checks=[_check(BOB, result=CheckResult.CONFIRMED.value, events=[_event()])])
    assert coverage.total == 2
    assert coverage.state is CoverageState.PARTIAL


@pytest.mark.unit
def test_every_requested_alert_gets_an_entry():
    result = assemble_coverage(["a", "b"], {"a": {ALICE}}, {}, {})
    assert set(result) == {"a", "b"}
    assert result["b"].total == 0


@pytest.mark.unit
def test_tooltip_truncates_long_recipient_lists():
    targets = [TargetCoverage(target=create_email_delivery("<m>", f"user{i}@example.com"), attempted=True)
               for i in range(TOOLTIP_TARGET_LIMIT + 5)]
    coverage = RemediationCoverage(targets=targets)
    lines = coverage.tooltip.split("\n")
    assert len(lines) == TOOLTIP_TARGET_LIMIT + 1
    assert lines[-1] == "... and 5 more"


@pytest.mark.integration
def test_get_remediation_coverage_reads_all_three_sources():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.add_observable_by_spec(F_EMAIL_DELIVERY, ALICE)
    root.add_observable_by_spec(F_EMAIL_DELIVERY, BOB)
    root.save()
    alert = ALERT(root)

    other_root = create_root_analysis(uuid=str(uuid.uuid4()))
    other_root.initialize_storage()
    other_root.save()
    other_alert = ALERT(other_root)

    db = get_db()

    # ACE removed alice's copy
    remediation = Remediation(
        type=F_EMAIL_DELIVERY,
        name="email_remediator",
        key=ALICE,
        action="remove",
        status="COMPLETED",
        result="SUCCESS",
        user_id=get_global_runtime_settings().automation_user_id,
    )
    db.add(remediation)
    db.flush()
    db.add(ObservableRemediationMapping(
        observable_id=upsert_observable(create_observable(F_EMAIL_DELIVERY, ALICE)),
        remediation_id=remediation.id,
    ))

    # a probe confirmed the vendor removed bob's copy
    db.add(ExternalRemediationCheck(
        probe_name="fake_probe",
        observable_type=F_EMAIL_DELIVERY,
        observable_value=BOB,
        alert_uuid=alert.uuid,
        status=CheckStatus.COMPLETED.value,
        result=CheckResult.CONFIRMED.value,
        events_json=json.dumps([_event(target="bob@example.com")]),
        max_retries=3,
        deadline=datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    db.commit()

    coverage = get_remediation_coverage([alert, other_alert])

    assert set(coverage) == {alert.uuid, other_alert.uuid}
    assert coverage[alert.uuid].state is CoverageState.REMEDIATED
    assert coverage[alert.uuid].label == "remediated 2/2 · ACE, Fake Source"
    assert coverage[other_alert.uuid].state is CoverageState.NONE
    assert get_remediation_coverage([]) == {}
