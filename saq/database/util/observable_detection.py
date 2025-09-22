from dataclasses import dataclass
from typing import Optional

from saq.analysis.observable import Observable
from saq.database.model import Observable as DBObservable, User
from saq.analysis.root import RootAnalysis
from saq.database.pool import get_db

# TODO: there should be a single way to add observables to the database
# see sync.py

def enable_observable_detection(observable: Observable, enabled_by_user_id: int, detection_context: str):
    """Enables detection for a given observable."""
    # find the existing user
    db = get_db()
    db_user = db.query(User).filter(User.id == enabled_by_user_id).one_or_none()
    if db_user is None:
        raise ValueError(f"User with id {enabled_by_user_id} not found")

    # find the existing observable
    db_observable = db.query(DBObservable).filter(DBObservable.sha256 == observable.sha256_bytes, DBObservable.type == observable.type).one_or_none()
    if db_observable is None:
        db_observable = DBObservable(
            type=observable.type,
            sha256=observable.sha256_bytes,
            value=observable.value.encode("utf8", errors="ignore"),
            for_detection=True,
            enabled_by=enabled_by_user_id,
            detection_context=detection_context)
    else:
        db_observable.for_detection = True
        db_observable.enabled_by = enabled_by_user_id
        db_observable.detection_context = detection_context
    
    db.add(db_observable)
    db.commit()

def disable_observable_detection(observable: Observable):
    """Disables detection for a given observable."""
    # find the existing observable
    db_observable = get_db().query(DBObservable).filter(DBObservable.sha256 == observable.sha256_bytes, DBObservable.type == observable.type).one_or_none()
    if db_observable is None:
        return

    db_observable.for_detection = False
    get_db().commit()

@dataclass
class ObservableDetection:
    observable_uuid: str
    for_detection: bool
    enabled_by: str
    detection_context: str

def get_all_observable_detections(alert: RootAnalysis):
    """Returns a dictionary of observable UUIDs and their detection statuses for a given alert."""
    return get_observable_detections(alert.all_observables)

def _match_observable(observables: list[Observable], db_observable: DBObservable) -> Optional[Observable]:
    """Utility function that returns the Observable object that matches the given database observable.
    The match is made on the type and the sha256_hash of the value of the observable."""
    for observable in observables:
        if observable.type == db_observable.type and observable.sha256_bytes == db_observable.sha256:
            return observable

    return None

def get_observable_detections(observables: list[Observable]) -> dict[str, ObservableDetection]:
    """Returns a dictionary of observable UUIDs and their detection statuses for a given list of observable UUIDs."""
    detections: dict[str, ObservableDetection] = {}

    # for efficiency, we query the database for all the observables that match the given list of observables by sha256_hash
    db_observables = get_db().query(DBObservable).filter(DBObservable.sha256.in_([observable.sha256_bytes for observable in observables])).all()

    # then we filter that list down to only the observables that match the given list of observables by type and sha256_hash
    for db_observable in db_observables:
        observable = _match_observable(observables, db_observable)
        if observable is None:
            continue

        detections[observable.uuid] = ObservableDetection(
            observable_uuid=observable.uuid,
            for_detection=db_observable.for_detection,
            enabled_by=db_observable.enabled_by_user.display_name if db_observable.enabled_by_user else "unknown",
            detection_context=db_observable.detection_context
        )

    return detections