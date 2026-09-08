from saq.database import get_db_connection
from saq.environment import get_global_runtime_settings
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_LOCAL_WORKLOAD
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class LocalWorkloadMonitor(ACEThreadedMonitor):
    def execute(self):
        workload = []

        with get_db_connection() as db:
            cursor = db.cursor()

            # incoming_workload is shared by every node, so this monitor reports only
            # the work collected by (and deliverable from) this node
            cursor.execute(
                "SELECT iwt.name, iw.mode, COUNT(*) FROM incoming_workload iw "
                "JOIN incoming_workload_type iwt ON iw.type_id = iwt.id "
                "WHERE iw.node_id = %s "
                "GROUP BY iwt.name, iw.mode ORDER BY iwt.name, iw.mode",
                (get_global_runtime_settings().saq_node_id,),
            )
            for workload_type, mode, count in cursor:
                workload.append({"type": workload_type, "mode": mode, "count": count})
            db.commit()

        emit_monitor(MONITOR_LOCAL_WORKLOAD, {"workload": workload})
