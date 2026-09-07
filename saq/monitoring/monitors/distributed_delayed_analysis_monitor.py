import os

from saq.database import get_db_connection
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DISTRIBUTED_DELAYED_ANALYSIS
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class DistributedDelayedAnalysisMonitor(ACEThreadedMonitor):
    def execute(self):
        with get_db_connection() as db:
            cursor = db.cursor()

            # this reports the whole cluster, not just the node it runs on. only one node
            # is meant to run the distributed monitors (see service_monitoring), so a
            # query scoped to the local node leaves everything the other nodes are waiting
            # on unreported -- and the scanners hold most of the delayed analysis.
            cursor.execute(
                "SELECT storage_dir, analysis_module, nodes.name, COUNT(*) FROM delayed_analysis "
                "JOIN nodes ON delayed_analysis.node_id = nodes.id "
                "GROUP BY storage_dir, analysis_module, nodes.name"
            )
            for storage_dir, analysis_module, node, count in cursor:
                emit_monitor(MONITOR_DISTRIBUTED_DELAYED_ANALYSIS, {
                    "uuid": os.path.basename(storage_dir),
                    # this column holds AnalysisModule.name, which is already the bare
                    # name -- removeprefix leaves it alone rather than slicing 16
                    # characters off the front of it, while still tolerating the
                    # config-section form if anything ever writes that instead
                    "module": analysis_module.removeprefix("analysis_module_"),
                    "node": node,
                    "count": count,
                })
            db.commit()
