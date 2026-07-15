"""Persistence helpers shared by the worker daemon and synchronous-first
analysis-module probes.

Translating a :class:`ProbeOutcome` into a check-row update is the same logic
regardless of who called the probe — extracting it keeps the worker and the
analysis modules in lock-step on terminal-vs-retry decisions.
"""
from datetime import UTC, datetime
import json
import logging
from typing import Optional

from saq.database.model import ExternalRemediationCheck
from saq.database.pool import get_db
from saq.remediation.external.types import (
    CheckResult,
    CheckStatus,
    ProbeOutcome,
    ProbeOutcomeKind,
)


def persist_probe_outcome(
    check_id: int,
    outcome: ProbeOutcome,
    *,
    retry_count: int,
    max_retries: int,
    now: Optional[datetime] = None,
) -> None:
    """Apply a single probe attempt's outcome to the check row and append a
    history entry.

    ``retry_count`` is the row's attempt count BEFORE this attempt. The
    function bumps it by one when writing back.
    """
    if now is None:
        now = datetime.now(UTC)

    next_retry_count = retry_count + 1
    kind = outcome.kind

    new_status: str
    new_result: Optional[str]
    events_json: Optional[str] = None
    last_error: Optional[str] = None
    result_message: Optional[str] = outcome.message

    if kind is ProbeOutcomeKind.FOUND_EVENTS:
        new_status = CheckStatus.COMPLETED.value
        new_result = CheckResult.CONFIRMED.value
        events_json = json.dumps(outcome.found_events)
    elif kind is ProbeOutcomeKind.NOT_FOUND:
        new_status = CheckStatus.COMPLETED.value
        new_result = CheckResult.NOT_FOUND.value
    elif kind is ProbeOutcomeKind.PENDING:
        new_status = CheckStatus.NEW.value
        new_result = None
    elif kind is ProbeOutcomeKind.PERMANENT_ERROR:
        last_error = outcome.permanent_error
        new_status = CheckStatus.COMPLETED.value
        new_result = CheckResult.ERROR.value
    else:  # TRANSIENT_ERROR
        last_error = outcome.transient_error
        if next_retry_count >= max_retries:
            new_status = CheckStatus.COMPLETED.value
            new_result = CheckResult.ERROR.value
        else:
            new_status = CheckStatus.NEW.value
            new_result = None

    update_values = dict(
        lock=None,
        lock_time=None,
        status=new_status,
        result=new_result,
        result_message=result_message,
        update_time=now,
        retry_count=next_retry_count,
    )
    if events_json is not None:
        update_values["events_json"] = events_json
    if last_error is not None:
        update_values["last_error"] = last_error

    get_db().execute(
        ExternalRemediationCheck.__table__.update()
        .values(**update_values)
        .where(ExternalRemediationCheck.id == check_id)
    )
    get_db().commit()


def finalize_expired(check_id: int, *, now: Optional[datetime] = None) -> None:
    """Mark a check COMPLETED+EXPIRED without invoking the probe.

    Called by the worker when it picks up a row whose ``deadline`` has passed.
    """
    if now is None:
        now = datetime.now(UTC)

    get_db().execute(
        ExternalRemediationCheck.__table__.update()
        .values(
            lock=None,
            lock_time=None,
            status=CheckStatus.COMPLETED.value,
            result=CheckResult.EXPIRED.value,
            update_time=now,
        )
        .where(ExternalRemediationCheck.id == check_id)
    )
    get_db().commit()
    logging.info("EXPIRED external_remediation_check.id=%d", check_id)
