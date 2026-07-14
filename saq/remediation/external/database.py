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

from saq.database.model import ExternalRemediationCheck
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
