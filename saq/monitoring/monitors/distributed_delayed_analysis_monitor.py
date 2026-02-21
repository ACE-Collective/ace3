import os

from saq.database import get_db_connection
from saq.environment import get_global_runtime_settings
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DISTRIBUTED_DELAYED_ANALYSIS
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class DistributedDelayedAnalysisMonitor(ACEThreadedMonitor):
    def execute(self):
        with get_db_connection() as db:
            cursor = db.cursor()

            cursor.execute(
                "SELECT storage_dir, analysis_module, COUNT(*) FROM delayed_analysis "
                "JOIN nodes ON delayed_analysis.node_id = nodes.id "
                "WHERE nodes.name = %s GROUP BY storage_dir, analysis_module",
                (get_global_runtime_settings().saq_node,),
            )
            for storage_dir, analysis_module, count in cursor:
                emit_monitor(MONITOR_DISTRIBUTED_DELAYED_ANALYSIS, {
                    "uuid": os.path.basename(storage_dir),
                    "module": analysis_module[len("analysis_module_"):],
                    "count": count,
                })
            db.commit()
