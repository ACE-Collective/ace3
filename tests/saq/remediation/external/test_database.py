import json
from datetime import datetime, timedelta, timezone

import pytest

from saq.database.model import ExternalRemediationCheck
from saq.database.pool import get_db
from saq.remediation.external.database import (
    cancel_external_check,
    cancel_external_checks_for_alert,
    get_external_check,
    get_external_check_by_observable,
    get_external_checks_for_alert,
    get_pending_external_check_by_observable,
    queue_external_check,
)
from saq.remediation.external.types import CheckResult, CheckStatus


@pytest.mark.integration
def test_queue_external_check(db_alert):
    check_id = queue_external_check(
        probe_name="fake_probe",
        observable_type="email_delivery",
        observable_value="<id-1>|alice@example.com",
        alert_uuid=db_alert.uuid,
        max_retries=10,
        deadline_seconds=3600,
    )

    row = get_external_check(check_id)
    assert row is not None
    assert row.probe_name == "fake_probe"
    assert row.status == CheckStatus.NEW.value
    assert row.result is None
    assert row.retry_count == 0
    assert row.max_retries == 10
    # deadline should be ~1 hour from now (allow generous slack for slow CI).
    # MySQL TIMESTAMP comes back tz-naive; treat it as UTC for the comparison.
    deadline = row.deadline if row.deadline.tzinfo else row.deadline.replace(tzinfo=timezone.utc)
    assert deadline > datetime.now(timezone.utc) + timedelta(minutes=30)


@pytest.mark.unit
def test_queue_requires_alert_uuid():
    with pytest.raises(ValueError, match="alert_uuid is required"):
        queue_external_check(
            probe_name="fake_probe",
            observable_type="email_delivery",
            observable_value="x",
            alert_uuid="",
            max_retries=1,
            deadline_seconds=60,
        )


@pytest.mark.integration
def test_queue_persists_context(db_alert):
    received = datetime(2026, 5, 18, 16, 6, 4, tzinfo=timezone.utc)
    check_id = queue_external_check(
        probe_name="fake_probe",
        observable_type="email_delivery",
        observable_value="<id-ctx>|alice@example.com",
        alert_uuid=db_alert.uuid,
        max_retries=10,
        deadline_seconds=3600,
        context={"recipient": "alice@example.com", "received_time": received},
    )

    row = get_external_check(check_id)
    assert row.context_json is not None
    payload = json.loads(row.context_json)
    assert payload["recipient"] == "alice@example.com"
    # Datetimes are serialized to ISO strings on write.
    assert payload["received_time"] == "2026-05-18T16:06:04+00:00"


@pytest.mark.integration
def test_queue_without_context_leaves_column_null(db_alert):
    check_id = queue_external_check(
        probe_name="fake_probe",
        observable_type="email_delivery",
        observable_value="<id-noctx>|alice@example.com",
        alert_uuid=db_alert.uuid,
        max_retries=10,
        deadline_seconds=3600,
    )

    row = get_external_check(check_id)
    assert row.context_json is None


@pytest.mark.integration
def test_queue_empty_context_leaves_column_null(db_alert):
    check_id = queue_external_check(
        probe_name="fake_probe",
        observable_type="email_delivery",
        observable_value="<id-emptyctx>|alice@example.com",
        alert_uuid=db_alert.uuid,
        max_retries=10,
        deadline_seconds=3600,
        context={},
    )

    row = get_external_check(check_id)
    assert row.context_json is None


@pytest.mark.unit
def test_queue_unserializable_context_raises(db_alert):
    class NotSerializable:
        pass

    with pytest.raises(TypeError, match="unserializable context value"):
        queue_external_check(
            probe_name="fake_probe",
            observable_type="email_delivery",
            observable_value="<id-bad>|alice@example.com",
            alert_uuid=db_alert.uuid,
            max_retries=1,
            deadline_seconds=60,
            context={"weird": NotSerializable()},
        )


@pytest.mark.integration
def test_pending_lookup_skips_completed(make_check, db_alert):
    completed = make_check(status=CheckStatus.COMPLETED.value, result=CheckResult.CONFIRMED.value)
    pending = make_check(status=CheckStatus.NEW.value)

    found = get_pending_external_check_by_observable(
        probe_name=pending.probe_name,
        observable_type=pending.observable_type,
        observable_value=pending.observable_value,
        alert_uuid=db_alert.uuid,
    )
    assert found is not None and found.id == pending.id

    # by_observable (any status) should still return the most recent — which
    # is the pending row we just added.
    any_found = get_external_check_by_observable(
        probe_name=pending.probe_name,
        observable_type=pending.observable_type,
        observable_value=pending.observable_value,
        alert_uuid=db_alert.uuid,
    )
    assert any_found is not None and any_found.id == pending.id

    # And the completed row is still retrievable when its observable_value is
    # queried explicitly.
    completed_found = get_external_check_by_observable(
        probe_name=completed.probe_name,
        observable_type=completed.observable_type,
        observable_value=completed.observable_value,
        alert_uuid=db_alert.uuid,
    )
    assert completed_found is not None and completed_found.id == completed.id


@pytest.mark.integration
def test_cancel_external_check(make_check):
    check = make_check()
    assert cancel_external_check(check.id) is True

    row = get_external_check(check.id)
    assert row.status == CheckStatus.COMPLETED.value
    assert row.result == CheckResult.CANCELLED.value

    # Idempotent: a second cancel is a no-op (already terminal).
    assert cancel_external_check(check.id) is False


@pytest.mark.integration
def test_cancel_external_check_missing_row_returns_false():
    assert cancel_external_check(999999999) is False


@pytest.mark.integration
def test_cancel_checks_for_alert_bulk(make_check, db_alert):
    a = make_check()
    b = make_check()
    c = make_check(status=CheckStatus.COMPLETED.value, result=CheckResult.CONFIRMED.value)

    cancelled = cancel_external_checks_for_alert(db_alert.uuid)
    assert cancelled == 2

    db = get_db()
    rows = {r.id: r for r in db.query(ExternalRemediationCheck).all()}
    assert rows[a.id].result == CheckResult.CANCELLED.value
    assert rows[b.id].result == CheckResult.CANCELLED.value
    # The already-confirmed row was left alone.
    assert rows[c.id].result == CheckResult.CONFIRMED.value


@pytest.mark.integration
def test_get_external_checks_for_alert_ordered(make_check, db_alert):
    first = make_check()
    second = make_check()
    third = make_check()

    rows = get_external_checks_for_alert(db_alert.uuid)
    assert [r.id for r in rows] == [first.id, second.id, third.id]


@pytest.mark.unit
def test_superseding_source_from_reason_round_trips_both_formats():
    from saq.remediation.external.database import (
        ace_supersede_reason,
        probe_supersede_reason,
        superseding_source_from_reason,
    )

    when = datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc)
    assert superseding_source_from_reason(probe_supersede_reason("msdefender", when)) == "msdefender"
    assert superseding_source_from_reason(ace_supersede_reason(42, when)) == "ACE"
    assert superseding_source_from_reason(None) is None
    assert superseding_source_from_reason("") is None
    assert superseding_source_from_reason("something else entirely") is None
