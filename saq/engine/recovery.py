"""Manager-owned recovery of lost work.

A RootAnalysis is "lost" when the worker that held its lock stopped refreshing the lock
(the process died, was killed after a timeout, or hung long enough that its keepalive
thread was starved) and the lock has since exceeded lock_timeout_seconds.
Recovery is owned by the managers, keyed on lock expiry rather than node health
so lost work is never stranded even on a healthy node.

Recovery is deliberately lightweight: the workload row for an in-flight item survives the
death of its worker (a SIGKILL'd worker never runs the finally that would clear it), so the
item is still queued -- it is only blocked by the stale lock. Reclaiming and releasing that
lock, in an ownership-aware way, makes the item claimable again by a worker for a clean
resume. If a *live* owner has legitimately re-taken the lock since it was listed, the
reclaim fails and recovery leaves it untouched.
"""

import logging
import uuid as uuidlib

from saq.database.util.locking import acquire_lock, get_expired_locks, release_lock
from saq.error import report_exception


def recover_lost_root(uuid: str) -> bool:
    """Recover a single lost root by clearing its expired lock so the still-queued workload
    item can be picked up again.

    Returns True if the lock was reclaimed and cleared, False if a live owner holds it now (or
    on error).
    """
    recovery_lock_uuid = str(uuidlib.uuid4())

    # reclaim the lock -- only succeeds if it is still expired (or unowned). if a live worker
    # has re-taken it since we listed it, this returns False and we leave it alone
    if not acquire_lock(uuid, recovery_lock_uuid, allow_expired_takeover=True):
        logging.info("skipping recovery of %s - lock is held by a live owner", uuid)
        return False

    # we now own the formerly-lost lock; releasing it frees the still-present workload item for
    # a worker to claim cleanly (workers only take free locks)
    release_lock(uuid, recovery_lock_uuid, ignore_lock_failure=True)
    logging.info("recovered lost work item %s", uuid)
    return True


def recover_expired_locks(node_id=None, node_ids=None) -> int:
    """Recover every lost root whose lock has expired, optionally restricted to a node.

    node_id restricts to a single node reclaiming its own lost work; node_ids restricts to a
    set of nodes (e.g. the primary node reclaiming orphans from stale nodes). With neither, all
    expired locks are considered (the primary node's global backstop). Returns the number of
    roots recovered.
    """
    try:
        expired = get_expired_locks(node_id=node_id, node_ids=node_ids)
    except Exception as e:
        logging.error("unable to list expired locks for recovery: %s", e)
        report_exception()
        return 0

    recovered = 0
    for row in expired:
        root_uuid = row[0]  # get_expired_locks returns (uuid, lock_uuid, node_id)
        try:
            if recover_lost_root(root_uuid):
                recovered += 1
        except Exception as e:
            logging.error("error recovering lost root %s: %s", root_uuid, e)
            report_exception()

    if recovered:
        logging.info("recovered %d lost work items (node_id=%s)", recovered, node_id)

    return recovered
