from typing import Optional

from sqlalchemy import func
from saq.database.model import Remediation, RemediationHistory, User
from saq.database.pool import get_db
from saq.observables.generator import create_observable
from saq.remediation.target import RemediationTarget, get_observable_remediation_interfaces
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus


def cancel_remediations(
    remediation_ids: list[int],
    comment: Optional[str] = None,
    user_id: Optional[int] = None,
) -> int:
    update_query = Remediation.__table__.update()
    update_query = update_query.where(
        Remediation.id.in_(remediation_ids),
        Remediation.status == RemediationStatus.IN_PROGRESS.value,
    ).values(
        status=RemediatorStatus.CANCELLED.remediation_status.value,
        result=RemediatorStatus.CANCELLED.value,
        update_time=func.NOW(),
    )

    user = get_db().query(User).filter(User.id == user_id).first()
    message = (
        comment
        if comment
        else (
            f"cancelled by {user.display_name}" if user else "cancelled by unknown user"
        )
    )

    for remediation_id in remediation_ids:
        get_db().add(
            RemediationHistory(
                remediation_id=remediation_id,
                result=RemediatorStatus.CANCELLED.value,
                status=RemediatorStatus.CANCELLED.remediation_status.value,
                message=message,
            )
        )

    get_db().execute(update_query)
    get_db().commit()
    return len(remediation_ids)


def retry_remediations(remediation_ids: list[int]) -> int:
    update_query = Remediation.__table__.update()
    update_query = update_query.where(
        Remediation.id.in_(remediation_ids),
        Remediation.status == RemediationStatus.COMPLETED.value,
    ).values(
        status=RemediationStatus.NEW.value,
        result=None,
        update_time=None,
        lock=None,
        lock_time=None,
    )

    # remediation history does not allow NULL value for the result column

    get_db().execute(update_query)
    get_db().commit()
    return len(remediation_ids)


def restore_remediations(remediation_ids: list[int]) -> int:
    # filter the remediation IDs down to only remediations with the "remove" action
    remediations = (
        get_db()
        .query(Remediation)
        .filter(
            Remediation.id.in_(remediation_ids),
            Remediation.action == RemediationAction.REMOVE.value,
            Remediation.result == RemediatorStatus.SUCCESS.value,
            Remediation.status == RemediationStatus.COMPLETED.value,
        )
        .all()
    )

    if not remediations:
        return 0

    for remediation in remediations:
        RemediationTarget(
            remediator_name=remediation.name,
            observable_type=remediation.type,
            observable_value=remediation.key,
        ).queue_remediation(
            RemediationAction.RESTORE, remediation.user_id, remediation.restore_key
        )

    return len(remediations)


def delete_remediations(remediation_ids: list[int]) -> int:
    delete_query = Remediation.__table__.delete().where(
        Remediation.id.in_(remediation_ids)
    )
    get_db().execute(delete_query)
    get_db().commit()
    return len(remediation_ids)

def mass_remediate_targets(observable_type: str, observable_values: list[str], user_id: int) -> int:
    total = 0
    for observable_value in observable_values:
        target_observable = create_observable(observable_type, observable_value)
        if not target_observable:
            # TODO communicate this back to the caller somehow
            continue

        for interface in get_observable_remediation_interfaces(observable_type):
            targets = interface.get_remediation_targets(target_observable)
            for target in targets:
                target.queue_remediation(RemediationAction.REMOVE, user_id)
                total += 1

    return total

def get_distinct_remediator_names() -> list[str]:
    """Returns the list of distinct remediator names."""
    return [remediation.name for remediation in get_db().query(Remediation.name).distinct().all()]

def get_distinct_remediation_types() -> list[str]:
    """Returns the list of distinct remediation types."""
    return [remediation.type for remediation in get_db().query(Remediation.type).distinct().all()]

def get_distinct_remediation_actions() -> list[str]:
    """Returns the list of distinct remediation actions."""
    return [action.value for action in RemediationAction]

def get_distinct_remediator_statuses() -> list[str]:
    """Returns the list of distinct remediator statuses."""
    return [result.value for result in RemediatorStatus]

def get_distinct_remediation_statuses() -> list[str]:
    """Returns the list of distinct remediation statuses."""
    return [status.value for status in RemediationStatus]

def get_distinct_analyst_names() -> list[str]:
    """Returns the list of distinct analyst display names from remediations."""
    return [
        user.display_name
        for user in get_db().query(User)
        .join(Remediation, User.id == Remediation.user_id)
        .filter(User.display_name.isnot(None))
        .distinct()
        .all()
        if user.display_name
    ]