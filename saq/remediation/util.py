from typing import Optional

from sqlalchemy import func
from saq.database.model import Remediation, RemediationHistory, User
from saq.database.pool import get_db
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus


def cancel_remediation(remediation_id: int, user_id: Optional[int] = None) -> bool:
    """Stops one remediation that has not completed: queued (NEW) or IN_PROGRESS. Records history
    only when it actually cancelled something. Returns False when the remediation does not exist
    or has already completed."""
    cancelled = get_db().execute(
        Remediation.__table__.update()
        .where(
            Remediation.id == remediation_id,
            Remediation.status != RemediationStatus.COMPLETED.value,
        )
        .values(
            status=RemediatorStatus.CANCELLED.remediation_status.value,
            result=RemediatorStatus.CANCELLED.value,
            update_time=func.NOW(),
        )
    ).rowcount
    if not cancelled:
        get_db().rollback()
        return False

    user = get_db().get(User, user_id) if user_id is not None else None
    get_db().add(
        RemediationHistory(
            remediation_id=remediation_id,
            result=RemediatorStatus.CANCELLED.value,
            status=RemediatorStatus.CANCELLED.remediation_status.value,
            message=f"cancelled by {user.display_name}" if user else "cancelled by unknown user",
        )
    )
    get_db().commit()
    return True


def retry_remediation(remediation_id: int) -> bool:
    """Queues a completed remediation again, as it was. Returns False when the remediation does
    not exist or has not completed."""
    retried = get_db().execute(
        Remediation.__table__.update()
        .where(
            Remediation.id == remediation_id,
            Remediation.status == RemediationStatus.COMPLETED.value,
        )
        .values(
            status=RemediationStatus.NEW.value,
            result=None,
            update_time=None,
            lock=None,
            lock_time=None,
        )
    ).rowcount
    # remediation history does not allow NULL value for the result column, so a retry records none
    get_db().commit()
    return bool(retried)


def restore_remediation(remediation_id: int, user_id: int) -> Optional[int]:
    """Queues a restore of what a removal removed, with the restore key that removal produced,
    attributed to user_id. Returns the id of the queued restore, or None when the remediation does
    not exist or is not a removal that succeeded."""
    removal = (
        get_db()
        .query(Remediation)
        .filter(
            Remediation.id == remediation_id,
            Remediation.action == RemediationAction.REMOVE.value,
            Remediation.status == RemediationStatus.COMPLETED.value,
            Remediation.result == RemediatorStatus.SUCCESS.value,
        )
        .one_or_none()
    )
    if removal is None:
        return None

    return RemediationTarget(
        remediator_name=removal.name,
        observable_type=removal.type,
        observable_value=removal.key,
    ).queue_remediation(RemediationAction.RESTORE, user_id, removal.restore_key)


def delete_remediations(remediation_ids: list[int]) -> int:
    delete_query = Remediation.__table__.delete().where(
        Remediation.id.in_(remediation_ids)
    )
    get_db().execute(delete_query)
    get_db().commit()
    return len(remediation_ids)
