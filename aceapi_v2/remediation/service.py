"""Remediation service (ACE API v2).

Sync helpers over the remediation tables and the configured remediators, run through
run_db_in_thread: finding the targets of alerts loads each alert's analysis tree from disk, and
saq.remediation writes through the synchronous get_db() session.
"""

from datetime import tzinfo

from fastapi import HTTPException
from sqlalchemy import select

from aceapi_v2.listing import Listing, filter_entries
from aceapi_v2.remediation.schemas import (
    ObservableKey,
    RemediationHistoryEntry,
    RemediationRow,
    RemediationSummary,
    RemediationTargetKey,
    RemediationTargetRead,
)
from saq.database.model import Remediation, RemediationHistory, User
from saq.database.pool import get_db
from saq.gui.filter_screens import REMEDIATIONS_SCREEN
from saq.observables.generator import create_observable
from saq.remediation.database import get_current_remediation, get_current_restore_key
from saq.remediation.filters import remediation_filter_conditions
from saq.remediation.remediator import get_remediator_by_name
from saq.remediation.target import (
    RemediationTarget,
    get_observable_remediation_targets,
    get_remediation_targets_by_alert_uuids,
)
from saq.remediation.types import RemediationAction
from saq.remediation.util import cancel_remediation, delete_remediations, restore_remediation, retry_remediation


def _summary(remediation: Remediation) -> RemediationSummary:
    return RemediationSummary(
        id=remediation.id, action=remediation.action, status=remediation.status, result=remediation.result)


def _remediator_display_name(target: RemediationTarget) -> str | None:
    try:
        return target.remediator.display_name
    except ValueError:
        # a target can name a remediator this node does not configure
        return None


def _target_reads(targets: list[RemediationTarget]) -> list[RemediationTargetRead]:
    result = []
    for target in targets:
        current = get_current_remediation(target)
        result.append(RemediationTargetRead(
            remediator=target.remediator_name,
            observable_type=target.observable_type,
            observable_value=target.observable_value,
            remediator_display_name=_remediator_display_name(target),
            current=_summary(current) if current is not None else None,
        ))
    return result


def lookup_targets(alert_uuids: list[str]) -> list[RemediationTargetRead]:
    """The remediation targets of the observables in these alerts, each with its latest remediation."""
    return _target_reads(get_remediation_targets_by_alert_uuids(alert_uuids))


def _observable(key: ObservableKey):
    try:
        return create_observable(key.type, key.value)
    except Exception:
        return None


def lookup_observable_targets(keys: list[ObservableKey]) -> list[RemediationTargetRead]:
    """The remediation targets of these observables, each with its latest remediation. A value its
    type rejects is a 422 that names every such value."""
    targets: set[RemediationTarget] = set()
    invalid = []
    for key in keys:
        observable = _observable(key)
        if observable is None:
            invalid.append(f"{key.type} {key.value!r}")
            continue
        targets.update(get_observable_remediation_targets(observable))

    if invalid:
        raise HTTPException(status_code=422, detail=f"invalid observables: {', '.join(invalid)}")

    return _target_reads(sorted(targets, key=lambda t: (t.remediator_name, t.observable_type, t.observable_value)))


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


def _require(remediation_id: int) -> Remediation:
    remediation = get_db().get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail=f"remediation {remediation_id} not found")
    return remediation


def _reloaded_summary(remediation_id: int) -> RemediationSummary:
    get_db().expire_all()
    return _summary(get_db().get(Remediation, remediation_id))


def cancel(remediation_id: int, user_id: int) -> RemediationSummary:
    """Stops a remediation that has not completed (see saq.remediation.util.cancel_remediation)."""
    _require(remediation_id)
    if not cancel_remediation(remediation_id, user_id):
        raise HTTPException(status_code=409, detail=f"remediation {remediation_id} has already completed")

    return _reloaded_summary(remediation_id)


def retry(remediation_id: int) -> RemediationSummary:
    """Queues a completed remediation again (see saq.remediation.util.retry_remediation)."""
    _require(remediation_id)
    if not retry_remediation(remediation_id):
        raise HTTPException(status_code=409, detail=f"remediation {remediation_id} has not completed")

    return _reloaded_summary(remediation_id)


def restore(remediation_id: int, user_id: int) -> RemediationSummary:
    """Queues a restore of what a successful removal removed, and returns it (see
    saq.remediation.util.restore_remediation)."""
    _require(remediation_id)
    restore_id = restore_remediation(remediation_id, user_id)
    if restore_id is None:
        raise HTTPException(status_code=409, detail=f"remediation {remediation_id} is not a removal that succeeded")

    return _reloaded_summary(restore_id)


def delete(remediation_id: int) -> RemediationSummary:
    """Deletes a remediation's record. Returns it as it was."""
    removed = _summary(_require(remediation_id))
    # a Core DELETE, as delete_remediations() issues: the database cascades the observable mapping,
    # which an ORM delete would instead try to orphan
    delete_remediations([remediation_id])
    return removed


#
# the Remediations page
#

def _row(row) -> RemediationRow:
    remediation, analyst = row
    return RemediationRow(
        id=remediation.id, remediator=remediation.name, observable_type=remediation.type,
        observable_value=remediation.key, action=remediation.action, status=remediation.status,
        result=remediation.result, analyst=analyst, insert_date=remediation.insert_date,
        update_time=remediation.update_time)


def prepare_listing(f: list[str], tz: tzinfo) -> Listing:
    """The remediations the share-link filters (f=) of the remediations screen select."""
    statement = select(Remediation, User.display_name).outerjoin(User, User.id == Remediation.user_id)
    for condition in remediation_filter_conditions(filter_entries(REMEDIATIONS_SCREEN, f), tz):
        statement = statement.where(condition)

    return Listing(statement=statement, id_column=Remediation.id, to_row=_row)


def history(remediation_id: int, limit: int) -> list[RemediationHistoryEntry]:
    """A remediation's latest attempts, newest first."""
    _require(remediation_id)
    rows = (
        get_db().query(RemediationHistory)
        .filter(RemediationHistory.remediation_id == remediation_id)
        .order_by(RemediationHistory.insert_date.desc(), RemediationHistory.id.desc())
        .limit(limit)
        .all()
    )
    return [RemediationHistoryEntry(insert_date=row.insert_date, result=row.result, status=row.status,
                                    message=row.message) for row in rows]
