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
    """

    def execute(self):
        for record in pool_health():
            emit_monitor(MONITOR_CAS_POOL, record)
