from saq.configuration.config import get_config
from saq.database import get_db_connection
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DISTRIBUTED_WORKLOAD
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class DistributedWorkloadMonitor(ACEThreadedMonitor):
    def execute(self):
        workload = []

        with get_db_connection() as db:
            cursor = db.cursor()

            cursor.execute(
                "SELECT analysis_mode, COUNT(*) FROM workload "
                "WHERE company_id = %s GROUP BY analysis_mode ORDER BY analysis_mode",
                (get_config().global_settings.company_id,),
            )
            for analysis_mode, count in cursor:
                workload.append({"analysis_mode": analysis_mode, "count": count})
            db.commit()

        emit_monitor(MONITOR_DISTRIBUTED_WORKLOAD, {"workload": workload})
