import logging
import os
import sys
import threading
import time
from typing import Optional
from saq.constants import ENV_ACE_IS_PRIMARY_NODE, VALID_NODE_EXPECTED_STATES, VALID_NODE_STATUSES
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.environment import get_global_runtime_settings


def is_primary_node() -> bool:
    """Return True when this container is configured as the primary node.

    Driven by the ENV_ACE_IS_PRIMARY_NODE environment variable, defaulting to
    the primary ("1") so single-node installs behave as before. Primary-only
    maintenance routines (e.g. global blob store GC) gate on this.
    """
    return os.environ.get(ENV_ACE_IS_PRIMARY_NODE, "1") == "1"


def warn_if_blob_store_not_multi_node_safe():
    """Log a warning when a multi-node cluster uses a node-local blob store.

    The pure-local LocalHardlinkBlobStore keeps spilled analysis-cache blobs on
    the node's own filesystem, so a blob written on one node is invisible to
    the others. Multi-node deployments need a global backend (e.g. S3)
    configured via analysis_cache.blob_store.
    """
    from saq.configuration.config import get_config
    if get_config().analysis_cache.blob_store is not None:
        return  # a pluggable (global) backend is configured

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM nodes")
        row = cursor.fetchone()
        node_count = row[0] if row else 0

    if node_count > 1:
        logging.warning(
            "analysis cache blob store is node-local (LocalHardlinkBlobStore) but %s "
            "nodes are registered; multi-node deployments need a global blob store "
            "backend configured via analysis_cache.blob_store (e.g. S3)",
            node_count,
        )


def initialize_node():
    """Populates get_global_runtime_settings().saq_node_id with the node ID for g(G_NODE). Optionally inserts the node into the database if it does not exist."""

    # have we already called this function?
    if get_global_runtime_settings().saq_node_id is not None:
        return

    get_global_runtime_settings().saq_node_id = None

    with get_db_connection() as db:
        c = db.cursor()
        # we always default to a local node so that it doesn't get used by remote nodes automatically
        c.execute("SELECT id FROM nodes WHERE name = %s", (get_global_runtime_settings().saq_node,))

        row = c.fetchone()
        if row is not None:
            get_global_runtime_settings().saq_node_id = row[0]
            logging.debug("got existing node id {} for {}".format(get_global_runtime_settings().saq_node_id, get_global_runtime_settings().saq_node))

        if get_global_runtime_settings().saq_node_id is None:
            execute_with_retry(db, c, """INSERT INTO nodes ( name, location, company_id, last_update ) 
                                        VALUES ( %s, %s, %s, NOW() )""", 
                            (get_global_runtime_settings().saq_node, get_global_runtime_settings().api_prefix, get_global_runtime_settings().company_id),
                            commit=True)

            c.execute("SELECT id FROM nodes WHERE name = %s", (get_global_runtime_settings().saq_node,))
            row = c.fetchone()
            if row is None:
                logging.critical("unable to allocate a node_id from the database")
                sys.exit(1)
            else:
                get_global_runtime_settings().saq_node_id = row[0]
                logging.info("allocated node id {} for {}".format(get_global_runtime_settings().saq_node_id, get_global_runtime_settings().saq_node))

def get_available_nodes(company_id, target_analysis_modes):
    assert isinstance(company_id, int)
    assert isinstance(target_analysis_modes, str) or isinstance(target_analysis_modes, list)
    if isinstance(target_analysis_modes, str):
        target_analysis_modes = [ target_analysis_modes ]

    sql = """
SELECT
    nodes.id, 
    nodes.name, 
    nodes.location, 
    nodes.any_mode,
    nodes.last_update,
    node_modes.analysis_mode,
    COUNT(workload.id) AS 'WORKLOAD_COUNT'
FROM
    nodes LEFT JOIN node_modes ON nodes.id = node_modes.node_id
    LEFT JOIN workload ON nodes.id = workload.node_id
WHERE
    nodes.company_id = %s
    AND nodes.status = 'running'
    AND ( nodes.any_mode OR node_modes.analysis_mode in ( {} ) )
GROUP BY
    nodes.id,
    nodes.name,
    nodes.location,
    nodes.any_mode,
    nodes.last_update,
    node_modes.analysis_mode
ORDER BY
    WORKLOAD_COUNT ASC,
    nodes.last_update ASC
""".format(','.join(['%s' for _ in target_analysis_modes]))

    params = [ company_id ]
    params.extend(target_analysis_modes)
    
    with get_db_connection() as db:
        c = db.cursor()
        c.execute(sql, tuple(params))
        return c.fetchall()

def get_node_included_analysis_modes(node_id: Optional[int]=None) -> list[str]:
    """Returns the analysis modes that have been specifically INCLUDED to this node.
    If no node is specified then the current node is assumed."""
    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT analysis_mode FROM node_modes WHERE node_id = %s", (node_id,))
        return [_[0] for _ in cursor.fetchall()]

def get_node_excluded_analysis_modes(node_id: Optional[int]=None) -> list[str]:
    """Returns the analysis modes that have been specifically EXCLUDED for this node.
    If no node is specified then the current node is assumed."""
    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT analysis_mode FROM node_modes_excluded WHERE node_id = %s", (node_id,))
        return [_[0] for _ in cursor.fetchall()]

def node_supports_any_analysis_mode(node_id: Optional[int]=None) -> bool:
    """Returns True if the given node referenced by ID supports any analysis mode.
    If no node is specified then the current node is assumed."""
    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT any_mode FROM nodes WHERE id = %s", (node_id,))
        result = cursor.fetchone()
        if result is None:
            raise RuntimeError(f"node with id {node_id} does not exist")

        return result[0] == 1 # mysql int as boolean

def assign_node_analysis_modes(node_id: Optional[int]=None, analysis_modes: Optional[list[str]]=None, excluded_analysis_modes: Optional[list[str]]=None):
    """Assigns the included and excluded analysis modes to the node referenced by ID.
    If node_id is None then the current node is assumed."""

    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id

    with get_db_connection() as db:
        cursor = db.cursor()

        # if we don't specificy any modes, then the default is to accept all modes
        any_mode = 1 if not analysis_modes else 0
        execute_with_retry(db, cursor, "UPDATE nodes SET any_mode = %s WHERE id = %s", (any_mode, node_id))

        execute_with_retry(db, cursor, "DELETE FROM node_modes WHERE node_id = %s", (node_id,))
        execute_with_retry(db, cursor, "DELETE FROM node_modes_excluded WHERE node_id = %s", (node_id,))

        if analysis_modes:
            for mode in analysis_modes:
                execute_with_retry(db, cursor, "INSERT INTO node_modes ( node_id, analysis_mode ) VALUES ( %s, %s )", (node_id, mode))

        if excluded_analysis_modes:
            for excluded_mode in excluded_analysis_modes:
                execute_with_retry(db, cursor, "INSERT INTO node_modes_excluded ( node_id, analysis_mode ) VALUES ( %s, %s )", (node_id, excluded_mode))

        db.commit()

#
# node status management (see the node drain feature)
#
# a node moves through the following statuses:
# starting: node is starting up
# running: node is running normally
# draining_collectors: collectors stop collecting new work and flush their backlog,
#                      the node still accepts new work so local-only collectors can flush
# draining: no new work may be assigned to the node, outstanding work is being completed
# drained: nothing outstanding, safe to shut down
# stopped: node is not running (set on graceful shutdown, or reconciled by the primary node)
#
# separately from status, each node carries an expected_state of online or offline. status
# is what the node IS; expected_state is what an operator says it SHOULD be. draining a node
# sets it to offline, resuming it or restarting the engine sets it back to online.
#
# the pair is what makes a planned shutdown distinguishable from a crash: both a drained
# node that was then shut down and a node that died land on status = stopped, so monitoring
# has to read expected_state to know whether anyone meant for it to be down.
#

def get_node_status(node_id: Optional[int]=None) -> Optional[str]:
    """Returns the status of the node referenced by ID, or None if the node does not exist.
    If no node is specified then the current node is assumed."""
    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id

    if node_id is None:
        return None

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT status FROM nodes WHERE id = %s", (node_id,))
        row = cursor.fetchone()
        return row[0] if row else None

# cache of node_id -> (expiration timestamp, status) used by get_node_status_cached
_node_status_cache = {}
_node_status_cache_lock = threading.Lock()

def get_node_status_cached(node_id: Optional[int]=None, ttl_seconds: float=10.0) -> Optional[str]:
    """Returns the status of the node referenced by ID, cached for ttl_seconds.
    Used by code paths that poll frequently (workers, collectors)."""
    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id

    if node_id is None:
        return None

    now = time.monotonic()
    with _node_status_cache_lock:
        cached = _node_status_cache.get(node_id)
        if cached is not None and now < cached[0]:
            return cached[1]

    status = get_node_status(node_id)
    with _node_status_cache_lock:
        _node_status_cache[node_id] = (now + ttl_seconds, status)

    return status

def clear_node_status_cache():
    """Clears the node status cache. Used by tests and after status transitions."""
    with _node_status_cache_lock:
        _node_status_cache.clear()

def set_node_status(node_id: int, status: str):
    """Unconditionally sets the status of the node. Used by the engine lifecycle
    (starting, running, stopped) where startup is always authoritative."""
    assert status in VALID_NODE_STATUSES

    with get_db_connection() as db:
        cursor = db.cursor()
        execute_with_retry(db, cursor, "UPDATE nodes SET status = %s WHERE id = %s", (status, node_id), commit=True)

    clear_node_status_cache()
    logging.info("node %s status set to %s", node_id, status)

def set_node_expected_state(node_id: int, expected_state: str):
    """Sets the operator intent for the node (online or offline). Independent of
    status: draining sets this to offline so that monitoring can tell a planned
    shutdown from a crash, since both end up with status = stopped."""
    assert expected_state in VALID_NODE_EXPECTED_STATES

    with get_db_connection() as db:
        cursor = db.cursor()
        execute_with_retry(db, cursor, "UPDATE nodes SET expected_state = %s WHERE id = %s",
                           (expected_state, node_id), commit=True)

    logging.info("node %s expected state set to %s", node_id, expected_state)

def transition_node_status(node_id: int, to_status: str, from_statuses: list[str]) -> bool:
    """Atomically transitions the status of the node from one of from_statuses to to_status.
    Returns True if the transition occurred, False otherwise."""
    assert to_status in VALID_NODE_STATUSES
    assert from_statuses and all(_ in VALID_NODE_STATUSES for _ in from_statuses)

    sql = "UPDATE nodes SET status = %s WHERE id = %s AND status IN ( {} )".format(
        ",".join(["%s" for _ in from_statuses]))
    params = [to_status, node_id]
    params.extend(from_statuses)

    with get_db_connection() as db:
        cursor = db.cursor()
        rowcount = execute_with_retry(db, cursor, sql, tuple(params), commit=True)

    if rowcount == 1:
        clear_node_status_cache()
        logging.info("node %s status transitioned to %s", node_id, to_status)
        return True

    return False

def check_and_advance_collectors_drained(node_id: int, collector_stale_seconds: int=120) -> bool:
    """Atomically transitions the node from draining_collectors to draining once
    every collector on the node has finished flushing its backlog: no live
    collector reports a status other than drained or stopped. Collectors with a
    stale status are ignored (they may have crashed). Returns True if the node
    was advanced to draining."""

    # warn about any collectors we are ignoring because their status is stale
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""SELECT name, status FROM collector_status
                          WHERE node_id = %s
                          AND status NOT IN ( 'drained', 'stopped' )
                          AND TIMESTAMPDIFF(SECOND, last_update, NOW()) > %s""",
                       (node_id, collector_stale_seconds))
        for name, status in cursor.fetchall():
            logging.warning("ignoring stale collector status for %s (status %s) on node %s -- "
                            "the collector may have crashed with an unflushed backlog", name, status, node_id)

        rowcount = execute_with_retry(db, cursor, """UPDATE nodes SET status = 'draining'
            WHERE id = %s AND status = 'draining_collectors'
            AND NOT EXISTS ( SELECT 1 FROM collector_status
                WHERE node_id = %s
                AND status NOT IN ( 'drained', 'stopped' )
                AND TIMESTAMPDIFF(SECOND, last_update, NOW()) <= %s )""",
            (node_id, node_id, collector_stale_seconds),
            commit=True)

    if rowcount == 1:
        clear_node_status_cache()
        logging.info("node %s collectors have finished draining -- node is now draining", node_id)
        return True

    return False

def revert_draining_if_collector_pending(node_id: int, collector_stale_seconds: int=120) -> bool:
    """Atomically transitions the node from draining back to draining_collectors
    if a live collector reports a status other than drained or stopped (e.g. a
    collector that crashed during the flush restarted with an unflushed backlog).
    Returns True if the node was reverted."""

    with get_db_connection() as db:
        cursor = db.cursor()
        rowcount = execute_with_retry(db, cursor, """UPDATE nodes SET status = 'draining_collectors'
            WHERE id = %s AND status = 'draining'
            AND EXISTS ( SELECT 1 FROM collector_status
                WHERE node_id = %s
                AND status NOT IN ( 'drained', 'stopped' )
                AND TIMESTAMPDIFF(SECOND, last_update, NOW()) <= %s )""",
            (node_id, node_id, collector_stale_seconds),
            commit=True)

    if rowcount == 1:
        clear_node_status_cache()
        logging.error("node %s has a collector with an unflushed backlog -- reverted to draining_collectors", node_id)
        return True

    return False

def check_and_mark_drained(node_id: int, expected_delayed_count: int=0, collector_stale_seconds: int=120) -> bool:
    """Atomically transitions the node from draining to drained if there is no
    outstanding work: no workload entries, exactly expected_delayed_count
    delayed analysis entries (the count of entries that could not be transferred
    because no compatible node exists -- these do not block drain), and no live
    collector that has not finished draining. Returns True if the node was
    marked as drained."""

    # warn about any collectors we are ignoring because their status is stale
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""SELECT name, status FROM collector_status
                          WHERE node_id = %s
                          AND status NOT IN ( 'drained', 'stopped' )
                          AND TIMESTAMPDIFF(SECOND, last_update, NOW()) > %s""",
                       (node_id, collector_stale_seconds))
        for name, status in cursor.fetchall():
            logging.warning("ignoring stale collector status for %s (status %s) on node %s -- "
                            "the collector may have crashed with an unflushed backlog", name, status, node_id)

        rowcount = execute_with_retry(db, cursor, """UPDATE nodes SET status = 'drained'
            WHERE id = %s AND status = 'draining'
            AND NOT EXISTS ( SELECT 1 FROM workload WHERE node_id = %s )
            AND ( SELECT COUNT(*) FROM delayed_analysis WHERE node_id = %s ) = %s
            AND NOT EXISTS ( SELECT 1 FROM collector_status
                WHERE node_id = %s
                AND status NOT IN ( 'drained', 'stopped' )
                AND TIMESTAMPDIFF(SECOND, last_update, NOW()) <= %s )""",
            (node_id, node_id, node_id, expected_delayed_count, node_id, collector_stale_seconds),
            commit=True)

    if rowcount == 1:
        clear_node_status_cache()
        logging.info("node %s has finished draining and is now drained", node_id)
        return True

    return False

def revert_drained_if_work_appeared(node_id: int) -> bool:
    """Atomically transitions the node from drained back to draining if new work
    has appeared on the node (e.g. a submission raced the drained check).
    Returns True if the node was reverted."""

    with get_db_connection() as db:
        cursor = db.cursor()
        rowcount = execute_with_retry(db, cursor, """UPDATE nodes SET status = 'draining'
            WHERE id = %s AND status = 'drained'
            AND EXISTS ( SELECT 1 FROM workload WHERE node_id = %s )""",
            (node_id, node_id),
            commit=True)

    if rowcount == 1:
        clear_node_status_cache()
        logging.error("node %s acquired new work after draining -- reverted to draining", node_id)
        return True

    return False

def reconcile_stale_node_statuses(stale_seconds: int) -> int:
    """Sets the status of any node with a stale heartbeat to stopped. Status is
    self-reported, so a crashed node would otherwise show its last status
    forever. Executed by the primary node. Returns the number of nodes
    reconciled."""

    with get_db_connection() as db:
        cursor = db.cursor()
        rowcount = execute_with_retry(db, cursor, """UPDATE nodes SET status = 'stopped'
            WHERE TIMESTAMPDIFF(SECOND, last_update, NOW()) > %s
            AND status IN ( 'starting', 'running', 'draining', 'drained' )""",
            (stale_seconds,),
            commit=True)

    if rowcount:
        clear_node_status_cache()
        logging.warning("reconciled %s nodes with stale heartbeats to stopped", rowcount)

    return rowcount

def update_collector_status(node_id: int, name: str, status: str, backlog_count: int):
    """Updates the status of a collector service running on a node. The status
    is reported to the central database so the engine's drained check and the
    API can see it (the collection database is local to the host in production)."""

    with get_db_connection() as db:
        cursor = db.cursor()
        execute_with_retry(db, cursor, """INSERT INTO collector_status ( node_id, name, status, backlog_count, last_update )
            VALUES ( %s, %s, %s, %s, NOW() ) AS new
            ON DUPLICATE KEY UPDATE
                status = new.status,
                backlog_count = new.backlog_count,
                last_update = NOW()""",
            (node_id, name, status, backlog_count),
            commit=True)

def get_collector_statuses(node_id: int) -> list[tuple[str, str, int, object]]:
    """Returns the list of (name, status, backlog_count, last_update) for the
    collector services that have reported status on the node referenced by ID."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""SELECT name, status, backlog_count, last_update
                          FROM collector_status WHERE node_id = %s ORDER BY name""", (node_id,))
        return list(cursor.fetchall())

def get_node_workload_counts(node_id: int) -> tuple[int, int]:
    """Returns the (workload count, delayed analysis count) for the node referenced by ID."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM workload WHERE node_id = %s", (node_id,))
        workload_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM delayed_analysis WHERE node_id = %s", (node_id,))
        delayed_count = cursor.fetchone()[0]
        return workload_count, delayed_count
