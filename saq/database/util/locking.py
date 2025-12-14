import logging
import os
from typing import Optional

import pymysql
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.environment import get_global_runtime_settings
from saq.error import report_exception


def acquire_lock(uuid: str, lock_uuid: str, lock_owner: Optional[str] = None) -> bool:
    """Locks a UUID for a given lock_uuid and lock_owner.
    If lock_owner is not provided, it will be set to the current process id.

    Parameters:
        uuid: The UUID of the object to lock.
        lock_uuid: The UUID of the lock. This is used to identify the lock in the database.
        lock_owner: The owner of the lock. This is used to identify the owner of the lock in the database.

    Returns:
        True if the lock was acquired, False otherwise.
    """
    if lock_owner is None:
        lock_owner = "{}-{}".format(os.getpid(), lock_uuid)

    try:
        with get_db_connection() as db:
            cursor = db.cursor()
            logging.info("requesting lock on {} with lock uuid {} owned by {}".format(uuid, lock_uuid, lock_owner))
            execute_with_retry(db, cursor, "INSERT INTO locks ( uuid, lock_uuid, lock_owner, lock_time ) VALUES ( %s, %s, %s, NOW() )", 
                              ( uuid, lock_uuid, lock_owner ), commit=True)

            logging.info("locked {} with {}".format(uuid, lock_uuid))
            return True

    except pymysql.err.IntegrityError:
        # if a lock already exists -- make sure it's owned by someone else
        try:
            with get_db_connection() as db:
                cursor = db.cursor()
                execute_with_retry(db, cursor, "SELECT lock_uuid, lock_owner, TIMESTAMPDIFF(SECOND, lock_time, NOW()) FROM locks WHERE uuid = %s", (uuid,))
                row = cursor.fetchone()
                if row:
                    current_lock_uuid, current_lock_owner, current_lock_timeout = row
                    logging.info("lock on {} already exists with lock uuid {} owned by {} (lock timeout: {} seconds) (global lock timeout: {} seconds)".format(
                        uuid,
                        current_lock_uuid,
                        current_lock_owner,
                        current_lock_timeout,
                        get_global_runtime_settings().lock_timeout_seconds))

                # assume we already own the lock -- this will be true in subsequent calls
                # to acquire the lock
                execute_with_retry(db, cursor, """
UPDATE locks 
SET 
    lock_time = NOW(),
    lock_uuid = %s,
    lock_owner = %s
WHERE 
    uuid = %s 
    AND ( lock_uuid = %s OR TIMESTAMPDIFF(SECOND, lock_time, NOW()) >= %s )
""", (lock_uuid, lock_owner, uuid, lock_uuid, get_global_runtime_settings().lock_timeout_seconds))
                db.commit()

                cursor.execute("SELECT lock_uuid, lock_owner FROM locks WHERE uuid = %s", (uuid,))
                row = cursor.fetchone()
                if row:
                    current_lock_uuid, current_lock_owner = row
                    if current_lock_uuid == lock_uuid:
                        logging.info("locked {} with {}".format(uuid, lock_uuid))
                        return True

                    # lock was acquired by someone else
                    logging.info("attempt to acquire lock {} with lock uuid {} failed (already locked by {}: {})".format(
                                 uuid, lock_uuid, current_lock_uuid, current_lock_owner))

                else:
                    # lock was acquired by someone else
                    logging.info("attempt to acquire lock {} failed".format(uuid))

                return False

        except Exception as e:
            logging.error("attempt to acquire lock failed: {}".format(e))
            report_exception()
            return False

    except Exception as e:
        logging.error("attempt to acquire lock failed: {}".format(e))
        report_exception()
        return False

def release_lock(uuid: str, lock_uuid: str, ignore_lock_failure: bool = False) -> bool:
    """Releases a lock acquired by acquire_lock.

    Parameters:
        uuid: The UUID of the object to release the lock on.
        lock_uuid: The UUID of the lock to release.

    Returns:
        True if the lock was released, False otherwise.
    """
    try:
        # make sure these are right
        if not isinstance(uuid, str) or not uuid:
            raise ValueError(f"attempting to release a lock on an invalid uuid: {uuid}")

        if not isinstance(lock_uuid, str) or not uuid:
            raise ValueError(f"attempting to release an invalid lock_uuid: {lock_uuid}")

        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(db, cursor, "DELETE FROM locks WHERE uuid = %s AND lock_uuid = %s", (uuid, lock_uuid,))
            db.commit()
            if cursor.rowcount == 1:
                logging.info("released lock on {}".format(uuid))
            else:
                if not ignore_lock_failure:
                    logging.warning("failed to release lock on {} with lock uuid {}".format(uuid, lock_uuid))

            return cursor.rowcount == 1
    except Exception as e:
        logging.error("unable to release lock {}: {}".format(uuid, e))
        report_exception()

    return False

def force_release_lock(uuid: str) -> bool:
    """Releases a lock acquired by acquire_lock without providing the lock_uuid."""
    try:
        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(db, cursor, "DELETE FROM locks WHERE uuid = %s", (uuid,))
            db.commit()
            if cursor.rowcount == 1:
                logging.info("forced released lock on {}".format(uuid))
            else:
                logging.info("failed to force release lock on {}".format(uuid))

            return cursor.rowcount == 1
    except Exception as e:
        logging.error("unable to force release lock {}: {}".format(uuid, e))
        report_exception()

    return False

def clear_expired_locks() -> int:
    """Clear any locks that have exceeded g_int(G_LOCK_TIMEOUT_SECONDS)."""
    with get_db_connection() as db:
        c = db.cursor()
        execute_with_retry(db, c, "DELETE FROM locks WHERE TIMESTAMPDIFF(SECOND, lock_time, NOW()) >= %s",
                                  (get_global_runtime_settings().lock_timeout_seconds,))
        db.commit()
        if c.rowcount:
            logging.info("removed {} expired locks".format(c.rowcount))

        return c.rowcount
