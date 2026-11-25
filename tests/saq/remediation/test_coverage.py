"""Tests for the per-alert remediation coverage used by the alert list badge."""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sqlalchemy import select

from saq.constants import F_EMAIL_DELIVERY, F_TEST, create_email_delivery
from saq.database.database_observable import upsert_observable
from saq.database.model import Alert, ExternalRemediationCheck, ObservableRemediationMapping, Remediation
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.configuration.config import get_config
from saq.observables.generator import create_observable
from saq.modules.email.constants import DELIVERY_EXPANDED, DELIVERY_FORWARDED, DELIVERY_NOT_JOURNALED
from saq.remediation.coverage import (
    ACE_SOURCE,
    TOOLTIP_TARGET_LIMIT,
    CoverageState,
    RemediationCoverage,
    TargetCoverage,
    assemble_coverage,
    get_remediation_coverage,
    journal_explains,
    remediation_filter_value,
)
from saq.remediation.external.database import ace_supersede_reason, probe_supersede_reason
from saq.remediation.external.types import CheckResult, CheckStatus
from saq.remediation.types import ALERT_REMEDIATION_FILTER_OPTIONS, REMEDIATION_SOURCE_ANY
from tests.saq.helpers import create_root_analysis, insert_alert_with_email_targets

ALICE = create_email_delivery("<msg-1@example.com>", "alice@example.com")
BOB = create_email_delivery("<msg-1@example.com>", "bob@example.com")
CAROL = create_email_delivery("<msg-1@example.com>", "carol@example.com")
ALERT_UUID = "alert-1"


def _ace_row(status="COMPLETED", result="SUCCESS", action="remove", name="email_remediator"):
    return SimpleNamespace(status=status, result=result, action=action, name=name)


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


def _assemble(targets=(ALICE, BOB), ace=None, checks=None, undelivered=None):
    return assemble_coverage(
        [ALERT_UUID],
        {ALERT_UUID: set(targets)},
        ace or {},
        {ALERT_UUID: checks or []},
        {ALERT_UUID: undelivered or {}},
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
    root = create_root_analysis()
    root.initialize_storage()
    root.add_observable_by_spec(F_EMAIL_DELIVERY, ALICE)
    root.add_observable_by_spec(F_EMAIL_DELIVERY, BOB)
    # not an email target, so it adds nothing to the counts
    root.add_observable_by_spec(F_TEST, "not an email")
    root.save()
    alert = ALERT(root)

    other_root = create_root_analysis()
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
        user_id=get_config().global_settings.automation_user_id,
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


# --- #1199: an address the journal shows did not receive its own copy ---

DL = create_email_delivery("<msg-1@example.com>", "dl@example.com")


@pytest.mark.unit
@pytest.mark.parametrize("reason, result, explains", [
    (None, "NOT_FOUND", False),
    (DELIVERY_EXPANDED, "SUCCESS", False),
    (DELIVERY_EXPANDED, "FAILED", True),
    (DELIVERY_EXPANDED, "ERROR", True),
    (DELIVERY_FORWARDED, "FAILED", True),
    (DELIVERY_FORWARDED, "NOT_FOUND", True),
    # an ERROR says nothing about the address, and a forwarding mailbox may keep a copy that
    # another journal report records
    (DELIVERY_FORWARDED, "ERROR", False),
    (DELIVERY_NOT_JOURNALED, "NOT_FOUND", True),
    # the copy may be in a real mailbox another journal report names, so a failure there stays one
    (DELIVERY_NOT_JOURNALED, "FAILED", False),
    (DELIVERY_NOT_JOURNALED, "ERROR", False),
])
def test_journal_explains(reason, result, explains):
    assert journal_explains(reason, result) is explains


@pytest.mark.unit
def test_failed_removal_of_a_distribution_list_is_left_out_of_the_count():
    coverage = _assemble(
        targets=(ALICE, DL),
        ace={ALICE: [_ace_row()], DL: [_ace_row(result="FAILED")]},
        undelivered={DL: DELIVERY_EXPANDED},
    )

    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.status_label == "remediated 1/1"
    assert "dl@example.com: distribution list; its members' copies are their own deliveries" in coverage.tooltip


@pytest.mark.unit
def test_failed_removal_of_an_unjournaled_address_is_still_a_failure():
    coverage = _assemble(
        targets=(ALICE, DL),
        ace={ALICE: [_ace_row()], DL: [_ace_row(result="FAILED")]},
        undelivered={DL: DELIVERY_NOT_JOURNALED},
    )

    assert coverage.state is CoverageState.FAILED


@pytest.mark.unit
@pytest.mark.parametrize("row", [_ace_row(status="IN_PROGRESS", result=None), _ace_row(result="SUCCESS")])
def test_an_undelivered_address_still_counts_while_pending_or_once_remediated(row):
    coverage = _assemble(targets=(ALICE, DL), ace={ALICE: [_ace_row()], DL: [row]}, undelivered={DL: DELIVERY_FORWARDED})

    assert coverage.total == 2


@pytest.mark.integration
def test_get_remediation_coverage_reads_the_delivery_tags():
    root = create_root_analysis()
    root.initialize_storage()
    root.add_observable_by_spec(F_EMAIL_DELIVERY, ALICE)
    root.add_observable_by_spec(F_EMAIL_DELIVERY, DL).add_tag("delivery_expanded")
    root.save()
    alert = ALERT(root)

    db = get_db()
    for key, result in ((ALICE, "SUCCESS"), (DL, "FAILED")):
        remediation = Remediation(type=F_EMAIL_DELIVERY, name="email_remediator", key=key, action="remove",
                                  status="COMPLETED", result=result,
                                  user_id=get_config().global_settings.automation_user_id)
        db.add(remediation)
        db.flush()
        db.add(ObservableRemediationMapping(
            observable_id=upsert_observable(create_observable(F_EMAIL_DELIVERY, key)),
            remediation_id=remediation.id,
        ))
    db.commit()

    coverage = get_remediation_coverage([alert])[alert.uuid]

    assert coverage.state is CoverageState.REMEDIATED
    assert coverage.label == "remediated 1/1 · ACE"


# --- the manage page's Remediation filter ---
#
# The column's rule exists twice: RemediationCoverage.filter_value for the page that shows it, and
# remediation_filter_value() for the query that filters on it. Every scenario here runs through
# both, so neither copy can change without the other.

NON_ASCII = create_email_delivery("<msg-ü@example.com>", "zoë@example.com")


def _scenario(targets=(ALICE, BOB), ace=None, checks=None, undelivered=None):
    return {"targets": targets, "ace": ace or {}, "checks": checks or [], "undelivered": undelivered or {}}


SCENARIOS = [
    pytest.param(_scenario(targets=()), "none", id="no_targets"),
    pytest.param(_scenario(), "none", id="no_activity"),
    pytest.param(_scenario(ace={ALICE: [_ace_row()], BOB: [_ace_row()]}), "remediated", id="ace_success"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(), _ace_row(action="restore")]}),
                 "not_remediated", id="restored_after_removal"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(result="FAILED"), _ace_row()]}),
                 "remediated", id="removed_after_failure"),
    pytest.param(_scenario(checks=[_check(ALICE, result=CheckResult.CONFIRMED.value, events=[_event()]),
                                   _check(BOB, status=CheckStatus.NEW.value)]),
                 "partial", id="confirmed_and_watching"),
    pytest.param(_scenario(ace={ALICE: [_ace_row(result="FAILED")], BOB: [_ace_row()]}), "failed", id="ace_failed"),
    pytest.param(_scenario(ace={ALICE: [_ace_row(result="ERROR")]}), "failed", id="ace_error"),
    pytest.param(_scenario(ace={ALICE: [_ace_row(result="FAILED")], BOB: [_ace_row()]},
                           checks=[_check(ALICE, result=CheckResult.CONFIRMED.value, events=[_event()])]),
                 "remediated", id="ace_failed_but_vendor_confirmed"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(result="NOT_FOUND")]}),
                 "not_in_mailbox", id="not_found"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(result="NOT_FOUND")]},
                           checks=[_check(ALICE, status=CheckStatus.NEW.value)]),
                 "not_in_mailbox", id="not_found_while_watching"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(result="NOT_FOUND")]},
                           checks=[_check(ALICE, result=CheckResult.CONFIRMED.value, events=[_event()])]),
                 "remediated", id="not_found_then_vendor_confirmed"),
    pytest.param(_scenario(ace={ALICE: [_ace_row(result="NOT_FOUND")], BOB: [_ace_row()]}),
                 "remediated", id="not_found_and_removed"),
    pytest.param(_scenario(targets=(ALICE, BOB, CAROL), ace={ALICE: [_ace_row(result="NOT_FOUND")], BOB: [_ace_row()]},
                           checks=[_check(CAROL, status=CheckStatus.NEW.value)]),
                 "partial", id="not_found_removed_and_watching"),
    pytest.param(_scenario(ace={ALICE: [_ace_row(result="NOT_FOUND")]}, checks=[_check(BOB, status=CheckStatus.NEW.value)]),
                 "not_in_mailbox", id="not_found_and_watching"),
    pytest.param(_scenario(checks=[_check(ALICE, status=CheckStatus.NEW.value),
                                   _check(BOB, status=CheckStatus.IN_PROGRESS.value)]),
                 "watching", id="probes_watching"),
    pytest.param(_scenario(ace={ALICE: [_ace_row(status="IN_PROGRESS", result=None)]},
                           checks=[_check(BOB, status=CheckStatus.IN_PROGRESS.value)]),
                 "remediating", id="removal_in_flight"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(status="NEW", result=None, action="restore")]}),
                 "watching", id="restore_in_flight"),
    pytest.param(_scenario(checks=[_check(ALICE, result=CheckResult.EXPIRED.value),
                                   _check(BOB, result=CheckResult.NOT_FOUND.value)]),
                 "not_remediated", id="probes_finished_unconfirmed"),
    pytest.param(_scenario(checks=[_check(ALICE, result=CheckResult.SUPERSEDED.value, result_message="???"),
                                   _check(BOB, result=CheckResult.SUPERSEDED.value, result_message="???")]),
                 "remediated", id="superseded"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(result=None)]}),
                 "not_remediated", id="completed_removal_without_a_result"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(result=None, action="restore")]}),
                 "not_remediated", id="completed_restore_without_a_result"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row(result="CANCELLED")]}),
                 "not_remediated", id="removal_cancelled"),
    pytest.param(_scenario(targets=(ALICE,), checks=[_check(BOB, result=CheckResult.CONFIRMED.value, events=[_event()])]),
                 "partial", id="check_only_target_confirmed"),
    pytest.param(_scenario(targets=(), checks=[_check(BOB, status=CheckStatus.NEW.value)]),
                 "watching", id="check_only_target_watching"),
    pytest.param(_scenario(targets=(), checks=[_check(BOB, result=CheckResult.EXPIRED.value),
                                               _check(BOB, result=CheckResult.CONFIRMED.value, events=[_event()])]),
                 "remediated", id="check_only_target_confirmed_by_a_sibling"),
    pytest.param(_scenario(targets=(ALICE,), ace={ALICE: [_ace_row()]}, checks=[_check(BOB, result=CheckResult.EXPIRED.value)]),
                 "partial", id="check_only_target_beside_a_removed_one"),
    pytest.param(_scenario(targets=(NON_ASCII,), checks=[_check(NON_ASCII, result=CheckResult.CONFIRMED.value,
                                                                 events=[_event()])]),
                 "remediated", id="non_ascii_value"),
    pytest.param(_scenario(targets=(ALICE, DL), ace={ALICE: [_ace_row()], DL: [_ace_row(result="FAILED")]},
                           undelivered={DL: DELIVERY_EXPANDED}),
                 "remediated", id="distribution_list_failure_left_out"),
    pytest.param(_scenario(targets=(ALICE, DL), ace={ALICE: [_ace_row()], DL: [_ace_row(result="FAILED")]},
                           undelivered={DL: DELIVERY_NOT_JOURNALED}),
                 "failed", id="unjournaled_failure_still_fails"),
    pytest.param(_scenario(targets=(ALICE, DL), ace={ALICE: [_ace_row()], DL: [_ace_row(result="ERROR")]},
                           undelivered={DL: DELIVERY_FORWARDED}),
                 "failed", id="forwarded_error_still_fails"),
    pytest.param(_scenario(targets=(ALICE, DL), ace={ALICE: [_ace_row()], DL: [_ace_row(status="IN_PROGRESS", result=None)]},
                           undelivered={DL: DELIVERY_FORWARDED}),
                 "partial", id="undelivered_address_still_counts_while_pending"),
    pytest.param(_scenario(targets=(ALICE, DL), ace={ALICE: [_ace_row()], DL: [_ace_row(result="FAILED")]},
                           checks=[_check(DL, status=CheckStatus.NEW.value)], undelivered={DL: DELIVERY_EXPANDED}),
                 "failed", id="undelivered_address_still_counts_while_a_probe_watches"),
    pytest.param(_scenario(targets=(ALICE, DL), ace={DL: [_ace_row(result="FAILED")]},
                           checks=[_check(DL, result=CheckResult.SUPERSEDED.value, result_message="???")],
                           undelivered={DL: DELIVERY_EXPANDED}),
                 "none", id="superseded_after_the_journal_left_it_out"),
]


@pytest.mark.unit
@pytest.mark.parametrize("scenario, expected", SCENARIOS)
def test_filter_value(scenario, expected):
    assert _assemble(**scenario).filter_value == expected


@pytest.mark.unit
def test_scenarios_cover_every_filter_value():
    assert {param.values[1] for param in SCENARIOS} == set(ALERT_REMEDIATION_FILTER_OPTIONS)


def _sql_filter_value(alert, source=REMEDIATION_SOURCE_ANY) -> str:
    return get_db().execute(select(remediation_filter_value(Alert, source)).where(Alert.id == alert.id)).scalar_one()


def _filter_values(alert) -> tuple[str, str]:
    """The alert's filter value as the column computes it (a page of one) and as the filter does."""
    return get_remediation_coverage([alert])[alert.uuid].filter_value, _sql_filter_value(alert)


@pytest.mark.integration
@pytest.mark.parametrize("scenario, expected", SCENARIOS)
def test_the_filter_agrees_with_the_column(scenario, expected):
    alert = insert_alert_with_email_targets(**scenario)
    assert _filter_values(alert) == (expected, expected)


@pytest.mark.integration
def test_the_filter_reads_only_the_alerts_own_checks_and_tags():
    # ACE's rows belong to the observable and show on every alert that maps it; checks and the
    # journal's delivery tags belong to the alert
    left_out = insert_alert_with_email_targets(
        (DL,), ace={DL: [_ace_row(result="FAILED")]}, undelivered={DL: DELIVERY_EXPANDED},
        checks=[_check(BOB, result=CheckResult.CONFIRMED.value, events=[_event()])])
    other = insert_alert_with_email_targets((BOB, DL))

    assert _filter_values(left_out) == ("remediated", "remediated")
    assert _filter_values(other) == ("failed", "failed")


@pytest.mark.integration
def test_the_filter_ignores_other_observable_types():
    alert = insert_alert_with_email_targets((ALICE,))
    db = get_db()
    remediation = Remediation(type="url", name="url_remediator", key=ALICE, action="remove", status="COMPLETED",
                              result="SUCCESS", user_id=get_config().global_settings.automation_user_id)
    db.add(remediation)
    db.flush()
    db.add(ObservableRemediationMapping(observable_id=upsert_observable(create_observable(F_EMAIL_DELIVERY, ALICE)),
                                        remediation_id=remediation.id))
    db.add(ExternalRemediationCheck(probe_name="fake_probe", observable_type="url", observable_value=ALICE,
                                    alert_uuid=alert.uuid, status=CheckStatus.COMPLETED.value,
                                    result=CheckResult.CONFIRMED.value, max_retries=3,
                                    deadline=datetime.now(timezone.utc) + timedelta(hours=1)))
    db.commit()

    root = create_root_analysis()
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "not an email")
    root.save()
    not_email = ALERT(root)

    assert _filter_values(alert) == ("none", "none")
    assert _filter_values(not_email) == ("none", "none")


@pytest.mark.integration
def test_a_check_only_target_never_takes_ace_rows():
    # ALICE is removed through the alert that maps it; the other alert only has a probe watching
    # for ALICE and does not map her, so for it ALICE is still being watched
    insert_alert_with_email_targets((ALICE,), ace={ALICE: [_ace_row()]})
    watching = insert_alert_with_email_targets((), checks=[_check(ALICE, status=CheckStatus.NEW.value)])

    assert _filter_values(watching) == ("watching", "watching")


# ACE's removal of ALICE failed and a probe confirmed it; another remediator removed BOB, whom another
# probe is still watching. Each source sees only its own rows.
MIXED_SOURCES = _scenario(
    ace={ALICE: [_ace_row(result="FAILED")], BOB: [_ace_row(name="other_remediator")]},
    checks=[_check(ALICE, result=CheckResult.CONFIRMED.value, events=[_event()]),
            _check(BOB, status=CheckStatus.NEW.value, probe_name="other_probe")],
)


def _from_source(scenario, source):
    """The scenario with only the source's rows: what the filter means by naming one."""
    if source == REMEDIATION_SOURCE_ANY:
        return scenario
    return dict(scenario,
                ace={target: [row for row in rows if row.name == source] for target, rows in scenario["ace"].items()},
                checks=[check for check in scenario["checks"] if check.probe_name == source])


@pytest.mark.integration
@pytest.mark.parametrize("source, expected", [
    (REMEDIATION_SOURCE_ANY, "remediated"),
    ("email_remediator", "failed"),
    ("other_remediator", "partial"),
    ("fake_probe", "partial"),
    ("other_probe", "watching"),
    ("nobody", "none"),
])
def test_a_source_reads_only_its_own_rows(source, expected):
    alert = insert_alert_with_email_targets(**MIXED_SOURCES)
    assert _assemble(**_from_source(MIXED_SOURCES, source)).filter_value == expected
    assert _sql_filter_value(alert, source) == expected


@pytest.mark.integration
@pytest.mark.parametrize("source", ["email_remediator", "fake_probe"])
@pytest.mark.parametrize("scenario, expected", SCENARIOS)
def test_the_filter_agrees_with_the_column_for_one_source(scenario, expected, source):
    alert = insert_alert_with_email_targets(**scenario)
    assert _sql_filter_value(alert, source) == _assemble(**_from_source(scenario, source)).filter_value
