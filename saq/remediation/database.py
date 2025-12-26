from typing import Optional

from sqlalchemy import func
from saq.database.database_observable import upsert_observable
from saq.database.model import ObservableRemediationMapping, Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.observables.generator import create_observable
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus

def queue_remediation(target: RemediationTarget, action: RemediationAction, user_id: int, restore_key: Optional[str]=None) -> int:
    remediation = Remediation(
        action=action.value,
        name=target.remediator_name,
        type=target.observable_type,
        key=target.observable_value,
        user_id=user_id,
        restore_key=restore_key
    )
    get_db().add(remediation)
    get_db().flush() # to get the id of the remediation

    database_id = upsert_observable(create_observable(target.observable_type, target.observable_value))

    or_mapping = ObservableRemediationMapping(
        observable_id=database_id,
        remediation_id=remediation.id)

    get_db().add(or_mapping)
    get_db().commit()
    return remediation.id

def get_current_remediation(target: RemediationTarget) -> Optional[Remediation]:
    """Returns the current remediation status of the given target."""
    return (
        get_db()
        .query(Remediation)
        .filter(
            Remediation.name == target.remediator_name,
            Remediation.type == target.observable_type,
            Remediation.key == target.observable_value
        )
        .order_by(Remediation.id.desc())
        .first()
    )

def get_remediation_history(target: "RemediationTarget") -> list[RemediationHistory]:
    """Returns the remediation history for the given target."""
    # Find remediation IDs that match the target
    remediation_subquery = (
        get_db()
        .query(Remediation.id)
        .filter(
            Remediation.name == target.remediator_name,
            Remediation.type == target.observable_type,
            Remediation.key == target.observable_value
        )
    )
    
    # Query remediation history for those remediation IDs
    history = (
        get_db()
        .query(RemediationHistory)
        .filter(RemediationHistory.remediation_id.in_(remediation_subquery))
        .order_by(RemediationHistory.insert_date.desc())
        .all()
    )
    
    return history

def cancel_current_remediation(target: RemediationTarget) -> bool:
    """Cancels the current remediation for the given target."""
    remediation = get_current_remediation(target)
    if remediation is None:
        return False

    update = Remediation.__table__.update()
    update = update.values(
        status=RemediationStatus.COMPLETED.value,
        result=RemediatorStatus.CANCELLED.value,
        update_time=func.NOW(),
    )
    update = update.where(Remediation.id == remediation.id)
    get_db().execute(update)
    get_db().commit()
    return True

def delete_current_remediation(target: RemediationTarget) -> bool:
    """Deletes the current remediation for the given target."""
    remediation = get_current_remediation(target)
    if remediation is None:
        return False

    delete = Remediation.__table__.delete().where(Remediation.id == remediation.id)
    get_db().execute(delete)
    get_db().commit()
    return True

def get_current_restore_key(target: RemediationTarget) -> Optional[str]:
    """Returns the current restore key for the given target."""
    db_result = (
        get_db()
        .query(Remediation)
        .filter(
            Remediation.name == target.remediator_name,
            Remediation.type == target.observable_type,
            Remediation.key == target.observable_value,
            Remediation.action == RemediationAction.REMOVE.value,
            Remediation.result == RemediatorStatus.SUCCESS.value
        )
        .order_by(Remediation.id.desc())
        .first()
    )

    if db_result is None:
        return None

    return db_result.restore_key