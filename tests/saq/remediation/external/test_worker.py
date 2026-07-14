import json
from datetime import datetime, timedelta, timezone

import pytest

from saq.database.pool import get_db
from saq.remediation.external.types import (
    CheckResult,
    CheckStatus,
    CheckWorkItem,
    ProbeOutcome,
)
from saq.remediation.external.worker import ExternalRemediationCheckWorker
from tests.saq.remediation.external.conftest import FakeProbe


def _work_item_from(check, max_retries=3, context=None):
    return CheckWorkItem(
        id=check.id,
        probe_name=check.probe_name,
        observable_type=check.observable_type,
        observable_value=check.observable_value,
        alert_uuid=check.alert_uuid,
        retry_count=check.retry_count,
        max_retries=max_retries,
        deadline=check.deadline,
        context=context,
    )


@pytest.mark.integration
def test_worker_confirms_and_stores_events(make_check):
    events_payload = [
        {"source": "fake", "event_type": "auto_remediated", "timestamp": "2026-05-13T12:00:00Z",
         "description": "Auto-Remediated", "target": "alice@example.com"}
    ]
    probe = FakeProbe(outcome_factory=lambda t: ProbeOutcome(found_events=events_payload))
    worker = ExternalRemediationCheckWorker(probe)

    check = make_check()
    worker.process(_work_item_from(check))

    db = get_db()
    db.refresh(check)
    assert check.status == CheckStatus.COMPLETED.value
    assert check.result == CheckResult.CONFIRMED.value
    assert json.loads(check.events_json) == events_payload


@pytest.mark.integration
def test_worker_not_found_terminates(make_check):
    probe = FakeProbe(outcome_factory=lambda t: ProbeOutcome(not_found=True))
    worker = ExternalRemediationCheckWorker(probe)

    check = make_check()
    worker.process(_work_item_from(check))

    db = get_db()
    db.refresh(check)
    assert check.status == CheckStatus.COMPLETED.value
    assert check.result == CheckResult.NOT_FOUND.value


@pytest.mark.integration
def test_worker_pending_re_queues(make_check):
    probe = FakeProbe(outcome_factory=lambda t: ProbeOutcome(pending=True, message="no events yet"))
    worker = ExternalRemediationCheckWorker(probe)

    check = make_check()
    worker.process(_work_item_from(check))

    db = get_db()
    db.refresh(check)
    # PENDING bounces the row back to NEW so the collector can pick it up
    # again after the backoff window. retry_count is bumped so the next
    # backoff is larger.
    assert check.status == CheckStatus.NEW.value
    assert check.result is None
    assert check.retry_count == 1


@pytest.mark.integration
def test_worker_transient_error_retries_then_terminates(make_check):
    probe = FakeProbe(outcome_factory=lambda t: ProbeOutcome(transient_error="boom"))
    worker = ExternalRemediationCheckWorker(probe)

    # First attempt: still below max_retries, row goes back to NEW.
    check = make_check(retry_count=0, max_retries=2)
    worker.process(_work_item_from(check, max_retries=2))
    db = get_db()
    db.refresh(check)
    assert check.status == CheckStatus.NEW.value
    assert check.last_error == "boom"
    assert check.retry_count == 1

    # Second attempt: retry_count becomes 2, hits max_retries -> COMPLETED+ERROR.
    worker.process(_work_item_from(check, max_retries=2))
    db.refresh(check)
    assert check.status == CheckStatus.COMPLETED.value
    assert check.result == CheckResult.ERROR.value
    assert check.retry_count == 2


@pytest.mark.integration
def test_worker_permanent_error_terminates_without_retries(make_check):
    """A permanent error finalizes the row as COMPLETED+ERROR on the first
    attempt, even with retries still available."""
    probe = FakeProbe(outcome_factory=lambda t: ProbeOutcome(
        permanent_error="read timeout", message="query timed out"))
    worker = ExternalRemediationCheckWorker(probe)

    check = make_check(retry_count=0, max_retries=30)
    worker.process(_work_item_from(check, max_retries=30))

    db = get_db()
    db.refresh(check)
    assert check.status == CheckStatus.COMPLETED.value
    assert check.result == CheckResult.ERROR.value
    assert check.retry_count == 1
    assert check.last_error == "read timeout"


@pytest.mark.integration
def test_worker_expired_does_not_call_probe(make_check):
    """Past-deadline rows are finalized without ever invoking the probe."""
    probe = FakeProbe(outcome_factory=lambda t: pytest.fail("probe must not be called"))
    worker = ExternalRemediationCheckWorker(probe)

    check = make_check(deadline=datetime.now(timezone.utc) - timedelta(seconds=1))
    worker.process(_work_item_from(check))

    db = get_db()
    db.refresh(check)
    assert check.status == CheckStatus.COMPLETED.value
    assert check.result == CheckResult.EXPIRED.value
    assert probe.calls == []


@pytest.mark.integration
def test_worker_forwards_context_to_probe(make_check):
    """Context attached to the work item must reach the probe so daemon-side
    re-polls see the same enrichment the sync analyzer provided."""
    probe = FakeProbe(outcome_factory=lambda t: ProbeOutcome(pending=True))
    worker = ExternalRemediationCheckWorker(probe)

    check = make_check()
    context = {"recipient": "alice@example.com",
               "received_time": "2026-05-18T16:06:04+00:00"}
    worker.process(_work_item_from(check, context=context))

    assert len(probe.calls) == 1
    assert probe.calls[0].context == context


@pytest.mark.integration
def test_worker_handles_probe_exception_as_transient(make_check):
    def boom(_target):
        raise RuntimeError("kaboom")
    probe = FakeProbe(outcome_factory=boom)
    worker = ExternalRemediationCheckWorker(probe)

    check = make_check(retry_count=0, max_retries=3)
    worker.process(_work_item_from(check, max_retries=3))
    db = get_db()
    db.refresh(check)
    # Treated as a transient error: row goes back to NEW, last_error captured.
    assert check.status == CheckStatus.NEW.value
    assert check.last_error and "RuntimeError" in check.last_error
