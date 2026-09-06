"""DB helpers for the external remediation check subsystem.

Mirrors :mod:`saq.file_collection.database` — short, transactional helpers that
front the ``ExternalRemediationCheck`` ORM model. Higher-level lifecycle
(locking, dispatch) lives in :mod:`saq.remediation.external.collector` and
:mod:`.worker`.
"""
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Optional

from sqlalchemy import func

from saq.database.model import ExternalRemediationCheck, Remediation
from saq.database.pool import get_db
from saq.remediation.external.types import CheckResult, CheckStatus


def _json_default(value: Any) -> str:
    """JSON encoder fallback that converts datetimes to ISO strings.

    Anything else unserializable raises ``TypeError`` — loud failure beats
    silently dropping probe context.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"unserializable context value of type {type(value).__name__}")


def queue_external_check(
    probe_name: str,
    observable_type: str,
    observable_value: str,
    alert_uuid: str,
    max_retries: int,
    deadline_seconds: int,
    context: Optional[dict] = None,
) -> int:
    """Create a NEW check row, returning its id. Dedup is the caller's job —
    use :func:`get_pending_external_check_by_observable` first to avoid stacking
    duplicate active checks for the same (probe, observable, alert) tuple.

    ``context`` is an opaque JSON-serializable dict frozen on the row at queue
    time and rehydrated as :attr:`ProbeTarget.context` on every later attempt,
    including background re-polls by the daemon. Each probe owns the contract
    for the keys it cares about — the persistence layer does not introspect.
    """
    if not alert_uuid:
        raise ValueError("alert_uuid is required for external remediation check")

    deadline = datetime.now(timezone.utc) + timedelta(seconds=deadline_seconds)
    check = ExternalRemediationCheck(
        probe_name=probe_name,
        observable_type=observable_type,
        observable_value=observable_value,
        alert_uuid=alert_uuid,
        max_retries=max_retries,
        deadline=deadline,
        context_json=json.dumps(context, default=_json_default) if context else None,
    )
    get_db().add(check)
    get_db().flush()
    get_db().commit()
    return check.id


def get_external_check(check_id: int) -> Optional[ExternalRemediationCheck]:
    return (
        get_db()
        .query(ExternalRemediationCheck)
        .filter(ExternalRemediationCheck.id == check_id)
        .first()
    )


def get_external_check_by_observable(
    probe_name: str,
    observable_type: str,
    observable_value: str,
    alert_uuid: str,
) -> Optional[ExternalRemediationCheck]:
    """Returns the most recent check (any status) for the given target tuple."""
    return (
        get_db()
        .query(ExternalRemediationCheck)
        .filter(
            ExternalRemediationCheck.probe_name == probe_name,
            ExternalRemediationCheck.observable_type == observable_type,
            ExternalRemediationCheck.observable_value == observable_value,
            ExternalRemediationCheck.alert_uuid == alert_uuid,
        )
        .order_by(ExternalRemediationCheck.id.desc())
        .first()
    )


def get_pending_external_check_by_observable(
    probe_name: str,
    observable_type: str,
    observable_value: str,
    alert_uuid: str,
) -> Optional[ExternalRemediationCheck]:
    """Returns the most recent non-COMPLETED check for the given target tuple,
    used as a dedup guard before :func:`queue_external_check`."""
    return (
        get_db()
        .query(ExternalRemediationCheck)
        .filter(
            ExternalRemediationCheck.probe_name == probe_name,
            ExternalRemediationCheck.observable_type == observable_type,
            ExternalRemediationCheck.observable_value == observable_value,
            ExternalRemediationCheck.alert_uuid == alert_uuid,
            ExternalRemediationCheck.status != CheckStatus.COMPLETED.value,
        )
        .order_by(ExternalRemediationCheck.id.desc())
        .first()
    )


# The supersede reason is stored verbatim on ``external_remediation_check.result_message``.
# ``superseding_source_from_reason`` reads it back, so the two formats and the parser
# live together here.
_PROBE_SUPERSEDE_PREFIX = "probe "
_ACE_SUPERSEDE_PREFIX = "ACE remediation id="


def probe_supersede_reason(probe_name: str, confirmed_at: Optional[datetime]) -> str:
    return f"{_PROBE_SUPERSEDE_PREFIX}{probe_name} confirmed remediation at {confirmed_at}"


def ace_supersede_reason(remediation_id: int, succeeded_at: Optional[datetime]) -> str:
    return f"{_ACE_SUPERSEDE_PREFIX}{remediation_id} (remove) succeeded at {succeeded_at}"


def superseding_source_from_reason(reason: Optional[str]) -> Optional[str]:
    """Recover who confirmed the remediation from a stored supersede reason:
    the sibling probe's registered name, or ``"ACE"``. ``None`` when the
    message is not one of ours."""
    if not reason:
        return None
    if reason.startswith(_ACE_SUPERSEDE_PREFIX):
        return "ACE"
    if reason.startswith(_PROBE_SUPERSEDE_PREFIX):
        rest = reason[len(_PROBE_SUPERSEDE_PREFIX):]
        probe_name, sep, _ = rest.partition(" confirmed remediation at ")
        if sep and probe_name:
            return probe_name
    return None


def find_superseding_confirmation(
    observable_type: str,
    observable_value: str,
    exclude_probe_name: str,
    confirmed_before: Optional[datetime] = None,
) -> Optional[str]:
    """A human-readable reason if this target's remediation is already confirmed
    by someone else, or None.

    Two sources supersede a still-pending probe: a sibling probe's CONFIRMED
    check row for the same target (any alert — the target identifies the email,
    not the alert), and a successful ACE-side remediation of the same target in
    the ``remediation`` table. Once either exists the email is gone and further
    polling is pure spend.

    ``confirmed_before`` is the supersession grace cutoff: a confirmation newer
    than it does not (yet) supersede. This matters because a vendor's own events
    can surface hours after a sibling's confirmation (vendor event pipelines
    ingest late, and vendors act on their own schedules), so an immediate
    supersede can erase real timeline entries the probe was about to find.
    """
    sibling_query = (
        get_db()
        .query(ExternalRemediationCheck)
        .filter(
            ExternalRemediationCheck.probe_name != exclude_probe_name,
            ExternalRemediationCheck.observable_type == observable_type,
            ExternalRemediationCheck.observable_value == observable_value,
            ExternalRemediationCheck.result == CheckResult.CONFIRMED.value,
        )
    )
    if confirmed_before is not None:
        sibling_query = sibling_query.filter(ExternalRemediationCheck.update_time <= confirmed_before)
    sibling = sibling_query.order_by(ExternalRemediationCheck.id.desc()).first()
    if sibling is not None:
        return probe_supersede_reason(sibling.probe_name, sibling.update_time)

    # the latest completed+successful action decides: a successful remove means the target is
    # gone; a successful restore after it means the target is back and polling should continue
    latest_query = (
        get_db()
        .query(Remediation)
        .filter(
            Remediation.type == observable_type,
            Remediation.key == observable_value,
            Remediation.status == "COMPLETED",
            Remediation.result == "SUCCESS",
        )
    )
    if confirmed_before is not None:
        latest_query = latest_query.filter(
            func.coalesce(Remediation.update_time, Remediation.insert_date) <= confirmed_before)
    latest = latest_query.order_by(Remediation.id.desc()).first()
    if latest is not None and latest.action == "remove":
        return ace_supersede_reason(latest.id, latest.update_time)

    return None


def get_external_checks_for_alert(alert_uuid: str) -> list[ExternalRemediationCheck]:
    """All checks (any status) for an alert. Used by the timeline aggregator
    and the UI footer."""
    return (
        get_db()
        .query(ExternalRemediationCheck)
        .filter(ExternalRemediationCheck.alert_uuid == alert_uuid)
        .order_by(ExternalRemediationCheck.id.asc())
        .all()
    )


def cancel_external_check(check_id: int) -> bool:
    """Mark a check COMPLETED+CANCELLED. Returns False if the row is missing or
    already terminal."""
    check = get_external_check(check_id)
    if check is None or check.status == CheckStatus.COMPLETED.value:
        return False

    update = ExternalRemediationCheck.__table__.update().values(
        status=CheckStatus.COMPLETED.value,
        result=CheckResult.CANCELLED.value,
        update_time=func.NOW(),
        lock=None,
        lock_time=None,
    ).where(ExternalRemediationCheck.id == check_id)
    get_db().execute(update)
    get_db().commit()
    return True


def cancel_external_checks_for_alert(alert_uuid: str) -> int:
    """Cancel all in-flight checks for one alert. Returns the number of rows
    affected. Used by the optional disposition sweep."""
    update = ExternalRemediationCheck.__table__.update().values(
        status=CheckStatus.COMPLETED.value,
        result=CheckResult.CANCELLED.value,
        update_time=func.NOW(),
        lock=None,
        lock_time=None,
    ).where(
        ExternalRemediationCheck.alert_uuid == alert_uuid,
        ExternalRemediationCheck.status != CheckStatus.COMPLETED.value,
    )
    result = get_db().execute(update)
    get_db().commit()
    return result.rowcount


def delete_external_check(check_id: int) -> bool:
    check = get_external_check(check_id)
    if check is None:
        return False
    get_db().execute(
        ExternalRemediationCheck.__table__.delete().where(
            ExternalRemediationCheck.id == check_id
        )
    )
    get_db().commit()
    return True
