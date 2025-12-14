import logging
import sys
from typing import Optional
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.environment import get_global_runtime_settings


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
