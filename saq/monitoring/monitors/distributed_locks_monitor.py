from saq.database import get_db_connection
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DISTRIBUTED_LOCKS
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class DistributedLocksMonitor(ACEThreadedMonitor):
    def execute(self):
        with get_db_connection() as db:
            cursor = db.cursor()

            # this reports the whole cluster, not just the node it runs on -- only one
            # node is meant to run the distributed monitors, and the scanners hold nearly
            # all of the locks.
            #
            # the locks table has no node_id, so the owning node comes from the lock_owner
            # prefix Worker._create_lock_manager writes ("<node>-worker-<name>"). node
            # names contain hyphens of their own, so that prefix cannot be split off in
            # code -- it is resolved against the real node names instead.
            #
            # this is a scalar subquery rather than a LEFT JOIN because one node name can
            # be a prefix of another ("db" and "db-readonly"): a join matches both and
            # reports the lock twice. longest name wins, which is the more specific node,
            # and a lock whose owner carries no node prefix at all (the embedding service
            # uses str(self)) gets NULL rather than being dropped.
            #
            # no query parameters here on purpose: pymysql only applies % formatting when
            # args are passed, so the '-%' literals are safe as written. adding a
            # parameter to this query means escaping them to '-%%'.
            cursor.execute(
                "SELECT locks.uuid, locks.lock_uuid, locks.lock_time, locks.lock_owner, "
                "(SELECT nodes.name FROM nodes "
                " WHERE locks.lock_owner LIKE CONCAT(nodes.name, '-%') "
                " ORDER BY CHAR_LENGTH(nodes.name) DESC LIMIT 1) "
                "FROM locks ORDER BY locks.lock_time"
            )
            for _uuid, lock_uuid, lock_time, lock_owner, node in cursor:
                emit_monitor(MONITOR_DISTRIBUTED_LOCKS, {
                    "uuid": _uuid,
                    "lock_uuid": lock_uuid,
                    "lock_time": str(lock_time),
                    "lock_owner": lock_owner,
                    "node": node,
                })
            db.commit()
