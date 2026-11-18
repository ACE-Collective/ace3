import logging

from saq.cas.health import pool_health
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_CAS_POOL
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class CASPoolMonitor(ACEThreadedMonitor):
    """Reports the index state of every content-addressed storage pool, one event per pool
    (docs/CAS.md, "Observability").

    The index is shared, so like the other distributed monitors this is meant to run on exactly
    one node and reports for the cluster. The node-local half (read cache, free disk) comes from
    `ace cas node-stats` on every node instead.

    gc_overdue is the field to alert on: unheld objects further past their grace than the hourly
    GC should ever let them get. It stays above zero when GC is failing, or when it runs nowhere
    because no node has ACE_IS_PRIMARY_NODE=1 -- a case in which every cron record still says
    success.

    A pool whose backend is node-local on a cluster of more than one live node is a
    misconfiguration that fills every other node's disk while GC reports success (docs/CAS.md,
    "Sharing between nodes"): each record carries node_local and live_nodes, and every run logs
    an ERROR for each such pool.
    """

    def execute(self):
        for record in pool_health():
            if record["node_local"] and record["live_nodes"] > 1:
                logging.error(
                    "cas pool %s has a node-local backend but %s nodes are live: only the primary collects its bytes, "
                    "so every other node keeps what it stores until its disk fills. a multi-node site gives the pool "
                    "a backend every node can reach (docs/CAS.md, \"Sharing between nodes\")",
                    record["pool"], record["live_nodes"],
                    extra={"cas_pool": record["pool"], "live_nodes": record["live_nodes"], "backend": record["backend"]})

            emit_monitor(MONITOR_CAS_POOL, record)
