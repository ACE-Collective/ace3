from saq.configuration.config import get_config
from saq.database import get_db_connection
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_NODE_STATUS
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class NodeStatusMonitor(ACEThreadedMonitor):
    """Reports the state of every node in the cluster, one event per node.

    This is what lets monitoring tell a planned outage from a failure. A node that is
    drained and then shut down and a node that crashed both end up at status = stopped
    (see reconcile_stale_node_statuses), so status alone is not enough -- the pair
    (status, expected_state) is. expected_state is set to offline by a drain and back to
    online by a resume or an engine restart.

    Reporting from the database rather than from each node is deliberate: a node that is
    off cannot report on itself, and those are exactly the nodes worth reporting on. Only
    one node runs the distributed monitors, and it reports for everyone.

    The emitted `node` is nodes.name, which in a deployment that sets `node: env:SAQ_NODE`
    is the same string fluent-bit stamps as the Splunk host (event_host: ${SAQ_NODE}).
    That equality is what lets these events be joined to every other stream by host.
    """

    def execute(self):
        with get_db_connection() as db:
            cursor = db.cursor()

            # the counts are scalar subqueries rather than joins: a node has many workload
            # and many delayed_analysis rows, so joining both at once multiplies them
            # together and reports a product instead of two counts.
            #
            # heartbeat age comes from TIMESTAMPDIFF rather than being computed against the
            # reporting node's clock, matching every other freshness check in
            # saq/database/util/node.py -- the database clock is the one all nodes share.
            cursor.execute(
                "SELECT "
                "  nodes.id, nodes.name, nodes.location, nodes.status, nodes.expected_state, "
                "  nodes.last_update, TIMESTAMPDIFF(SECOND, nodes.last_update, NOW()), "
                "  nodes.is_primary, nodes.any_mode, "
                "  ( SELECT COUNT(*) FROM workload WHERE workload.node_id = nodes.id ), "
                "  ( SELECT COUNT(*) FROM delayed_analysis WHERE delayed_analysis.node_id = nodes.id ) "
                "FROM nodes WHERE nodes.company_id = %s ORDER BY nodes.name",
                (get_config().global_settings.company_id,),
            )

            for (node_id, name, location, status, expected_state, last_update, heartbeat_age,
                 is_primary, any_mode, workload_count, delayed_analysis_count) in cursor:
                emit_monitor(MONITOR_NODE_STATUS, {
                    "node": name,
                    "node_id": node_id,
                    "location": location,
                    "status": status,
                    "expected_state": expected_state,
                    "last_update": str(last_update),
                    "heartbeat_age_seconds": heartbeat_age,
                    "is_primary": bool(is_primary),
                    "any_mode": bool(any_mode),
                    "workload_count": workload_count,
                    "delayed_analysis_count": delayed_analysis_count,
                })

            db.commit()
