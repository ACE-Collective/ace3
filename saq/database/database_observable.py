from typing import Optional

from pymysql import IntegrityError
from sqlalchemy import func

from saq.analysis.disposition_history import DispositionHistory
from saq.analysis.observable import Observable
from saq.constants import DISPOSITION_UNKNOWN
from saq.database.model import (
    Alert as DBAlert,
    Observable as DBObservable,
    ObservableMapping,
)
from saq.database.pool import get_db, get_db_connection

def upsert_observable(observable: Observable) -> int:
    """Upserts an observable into the database. Returns the database id of the observable."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id FROM observables WHERE type = %s AND sha256 = %s", (observable.type, observable.sha256_bytes))
        result = cursor.fetchone()
        if result:
            return result[0]

        try:
            cursor.execute("INSERT INTO observables (`type`, `value`, `sha256`) VALUES (%s, %s, %s)", (observable.type, observable.value, observable.sha256_bytes))
            db.commit()
            return cursor.lastrowid
        except IntegrityError:
            cursor.execute("SELECT id FROM observables WHERE type = %s AND sha256 = %s", (observable.type, observable.sha256_bytes))
            result = cursor.fetchone()
            if result:
                return result[0]

        raise ValueError(f"Failed to upsert observable: {observable.type} {observable.value} {observable.sha256_bytes}")

def observable_is_set_for_detection(observable: Observable) -> bool:
    """Returns True if the observable is set for detection, False otherwise."""
    with get_db_connection() as db:
        cursor = db.cursor()
        # NOTE: the type predicate matters. This used to match on the hash alone, so a value enabled
        # for detection as one type reported as enabled for every type sharing that value.
        cursor.execute(
            "SELECT 1 FROM observable_detections WHERE type = %s AND value_sha256 = %s",
            (observable.type, observable.sha256_bytes))
        return cursor.fetchone() is not None

def get_observable_disposition_history(observable: Observable) -> Optional[DispositionHistory]:
    """Returns a DispositionHistory object if self.obj is an Observable, None otherwise."""
    if observable.whitelisted:
        return None

    result = DispositionHistory(observable)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
    SELECT 
        a.disposition, COUNT(*) 
    FROM 
        observables o JOIN observable_mapping om ON o.id = om.observable_id
        JOIN alerts a ON om.alert_id = a.id
    WHERE 
        o.type = %s AND 
        o.sha256 = UNHEX(%s) AND
        a.alert_type != 'faqueue' AND
        a.disposition != 'UNKNOWN'
    GROUP BY a.disposition""", (observable.type, observable.sha256_hash))

        for row in cursor:
            disposition, count = row
            result[disposition] = count

    return result

def get_observable_disposition_histories(observables: list[Observable]) -> dict[str, DispositionHistory]:
    """Returns observable uuid -> DispositionHistory for the given observables, in one query.

    The batched form of get_observable_disposition_history(). The alert view reads the
    history twice per rendered observable node, so on a large alert the per-observable
    form issued hundreds of 3-table aggregate joins for one page.

    Observables that are whitelisted, or that appear in no dispositioned alert, are absent
    from the result -- matching the per-observable function, which returns None for the
    first and an empty (falsy) DispositionHistory for the second.
    """
    histories: dict[str, DispositionHistory] = {}
    candidates = [observable for observable in observables if not observable.whitelisted]
    if not candidates:
        return histories

    # Query by hash alone (one indexed IN), then match on type as well -- the same shape as
    # get_observable_detections(), since a hash can be shared across types. sha256_bytes is
    # what the observables.sha256 column holds (see FileObservable.sha256_bytes), so this
    # matches the same rows as the per-observable form's `o.sha256 = UNHEX(sha256_hash)`.
    hashes = {observable.sha256_bytes for observable in candidates}
    rows = get_db().query(
        DBObservable.type,
        DBObservable.sha256,
        DBAlert.disposition,
        func.count(),
    ).join(
        ObservableMapping, ObservableMapping.observable_id == DBObservable.id,
    ).join(
        DBAlert, DBAlert.id == ObservableMapping.alert_id,
    ).filter(
        DBObservable.sha256.in_(hashes),
        DBAlert.alert_type != 'faqueue',
        DBAlert.disposition != DISPOSITION_UNKNOWN,
    ).group_by(
        DBObservable.type,
        DBObservable.sha256,
        DBAlert.disposition,
    ).all()

    counts_by_identity: dict[tuple, dict] = {}
    for observable_type, sha256, disposition, count in rows:
        counts_by_identity.setdefault((observable_type, sha256), {})[disposition] = count

    for observable in candidates:
        counts = counts_by_identity.get((observable.type, observable.sha256_bytes))
        if not counts:
            continue

        history = DispositionHistory(observable)
        for disposition, count in counts.items():
            history[disposition] = count

        histories[observable.uuid] = history

    return histories
