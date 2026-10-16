"""Remediation service (ACE API v2).

Sync helpers over the remediation tables and the configured remediators, run through
run_db_in_thread: finding the targets of alerts loads each alert's analysis tree from disk, and
saq.remediation writes through the synchronous get_db() session.
"""

from fastapi import HTTPException

from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.observables.generator import create_observable
from saq.remediation.database import get_current_remediation, get_current_restore_key
from saq.remediation.remediator import get_remediator_by_name
from saq.remediation.target import RemediationTarget, get_remediation_targets_by_alert_uuids
from saq.remediation.types import RemediationAction
from saq.remediation.util import cancel_remediation, delete_remediations
from aceapi_v2.remediation.schemas import (
    RemediationSummary,
    RemediationTargetKey,
    RemediationTargetRead,
)


def _summary(remediation: Remediation) -> RemediationSummary:
    return RemediationSummary(
        id=remediation.id, action=remediation.action, status=remediation.status, result=remediation.result)


def _remediator_display_name(target: RemediationTarget) -> str | None:
    try:
        return target.remediator.display_name
    except ValueError:
        # a target can name a remediator this node does not configure
        return None


def lookup_targets(alert_uuids: list[str]) -> list[RemediationTargetRead]:
    """The remediation targets of the observables in these alerts, each with its latest remediation."""
    result = []
    for target in get_remediation_targets_by_alert_uuids(alert_uuids):
        current = get_current_remediation(target)
        result.append(RemediationTargetRead(
            remediator=target.remediator_name,
            observable_type=target.observable_type,
            observable_value=target.observable_value,
            remediator_display_name=_remediator_display_name(target),
            current=_summary(current) if current is not None else None,
        ))
    return result


def _target(key: RemediationTargetKey) -> RemediationTarget:
    """A target from the request, checked before anything is queued: a remediator this node does
    not configure, or a value the observable type rejects, would fail in the remediation service."""
    try:
        get_remediator_by_name(key.remediator)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        observable = create_observable(key.observable_type, key.observable_value)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"invalid {key.observable_type} value: {e}")
    if observable is None:
        raise HTTPException(status_code=422, detail=f"invalid {key.observable_type} value {key.observable_value!r}")

    return RemediationTarget(key.remediator, key.observable_type, key.observable_value)


def queue_remediations(action: RemediationAction, keys: list[RemediationTargetKey], user_id: int) -> list[RemediationSummary]:
    """Queues one remediation per target, after checking every target, and returns them."""
    targets = [_target(key) for key in keys]

    remediation_ids = []
    for target in targets:
        # XXX a restore uses the restore key of the target's latest successful removal, which is
        # not guaranteed to be the removal the analyst means to undo
        restore_key = get_current_restore_key(target) if action == RemediationAction.RESTORE else None
        remediation_ids.append(target.queue_remediation(action, user_id, restore_key))

    remediations = {r.id: r for r in get_db().query(Remediation).filter(Remediation.id.in_(remediation_ids))}
    return [_summary(remediations[remediation_id]) for remediation_id in remediation_ids]


def cancel(remediation_id: int, user_id: int) -> RemediationSummary:
    """Stops a remediation that has not completed (see saq.remediation.util.cancel_remediation)."""
    if get_db().get(Remediation, remediation_id) is None:
        raise HTTPException(status_code=404, detail="remediation not found")

    if not cancel_remediation(remediation_id, user_id):
        raise HTTPException(status_code=409, detail=f"remediation {remediation_id} has already completed")

    get_db().expire_all()
    return _summary(get_db().get(Remediation, remediation_id))


def delete(remediation_id: int) -> RemediationSummary:
    """Deletes a remediation's record (the dialog's Clear). Returns it as it was."""
    remediation = get_db().get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail="remediation not found")

    removed = _summary(remediation)
    # a Core DELETE, as delete_remediations() issues: the database cascades the observable mapping,
    # which an ORM delete would instead try to orphan
    delete_remediations([remediation_id])
    return removed
