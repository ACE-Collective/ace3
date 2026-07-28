from typing import Optional

from pymysql import IntegrityError
from saq.analysis.disposition_history import DispositionHistory
from saq.analysis.observable import Observable
from saq.database.pool import get_db_connection

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
