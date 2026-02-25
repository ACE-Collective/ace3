from saq.constants import DB_COLLECTION
from saq.database import get_db_connection
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_LOCAL_WORKLOAD
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class LocalWorkloadMonitor(ACEThreadedMonitor):
    def execute(self):
        workload = []

        with get_db_connection(DB_COLLECTION) as db:
            cursor = db.cursor()

            cursor.execute(
                "SELECT iwt.name, iw.mode, COUNT(*) FROM incoming_workload iw "
                "JOIN incoming_workload_type iwt ON iw.type_id = iwt.id "
                "GROUP BY iwt.name, iw.mode ORDER BY iwt.name, iw.mode",
            )
            for workload_type, mode, count in cursor:
                workload.append({"type": workload_type, "mode": mode, "count": count})
            db.commit()

        emit_monitor(MONITOR_LOCAL_WORKLOAD, {"workload": workload})
