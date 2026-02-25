from saq.database import get_db_connection
from saq.environment import get_global_runtime_settings
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DISTRIBUTED_LOCKS
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class DistributedLocksMonitor(ACEThreadedMonitor):
    def execute(self):
        with get_db_connection() as db:
            cursor = db.cursor()

            cursor.execute(
                "SELECT uuid, lock_uuid, lock_time, lock_owner FROM locks "
                "WHERE lock_owner LIKE CONCAT(%s, '-%%') ORDER BY lock_time",
                (get_global_runtime_settings().saq_node,),
            )
            for _uuid, lock_uuid, lock_time, lock_owner in cursor:
                emit_monitor(MONITOR_DISTRIBUTED_LOCKS, {
                    "uuid": _uuid,
                    "lock_uuid": lock_uuid,
                    "lock_time": str(lock_time),
                    "lock_owner": lock_owner,
                })
            db.commit()
