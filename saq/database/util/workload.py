import logging
from typing import TYPE_CHECKING
from saq.configuration.config import get_engine_config
from saq.database.retry import execute_with_retry
from saq.database.util.node import initialize_node
from saq.environment import get_global_runtime_settings
from saq.database.pool import get_db_connection

if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis


def add_workload(root: "RootAnalysis"):
    """Adds the given work item to the workload queue.
       This will create an node entry if one does not exist for the current engine.
       If no engine is loaded then a local engine is assumed."""

    from saq.analysis.root import RootAnalysis
    assert isinstance(root, RootAnalysis), f"root must be a RootAnalysis, got {type(root)}"

    # if we don't specify an analysis mode then we default to whatever the engine default is
    # NOTE you should always specify an analysis mode
    if root.analysis_mode is None:
        logging.warning(f"missing analysis mode for call to add_workload({root}) - "
                        f"using engine default {get_engine_config().default_analysis_mode}")
        root.analysis_mode = get_engine_config().default_analysis_mode

    # make sure we've initialized our node id
    if get_global_runtime_settings().saq_node_id is None:
        initialize_node()
        
    with get_db_connection() as db:
        c = db.cursor()
        execute_with_retry(db, c, """
INSERT INTO workload (
    uuid,
    node_id,
    analysis_mode,
    company_id,
    storage_dir,
    insert_date )
VALUES ( %s, %s, %s, %s, %s, NOW() )
ON DUPLICATE KEY UPDATE uuid=uuid""", (root.uuid, get_global_runtime_settings().saq_node_id, root.analysis_mode, root.company_id, root.storage_dir))
        db.commit()
        logging.info("added {} to workload with analysis mode {} company_id {}".format(
                      root.uuid, root.analysis_mode, root.company_id))

def clear_workload_by_pid(pid):
    """Utility function that clears (deletes) any workload items currently being processed by the given process
       identified by pid. This is accomplished by querying the lock_owner column of the locks table and then
       find workload items for the uuids found.

       This is typically used to clear out error conditions."""
    
    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT uuid FROM locks WHERE lock_owner LIKE CONCAT('%%-', %s)", (pid,))
        for row in c:
            uuid = row[0]
            logging.warning(f"clearing workload item {uuid}")
            execute_with_retry(db, c, "DELETE FROM workload WHERE uuid = %s", (uuid,))

        logging.warning(f"clearing locks for pid {pid}")
        execute_with_retry(db, c, "DELETE FROM locks WHERE lock_owner LIKE CONCAT('%%-', %s)", (pid,))
        db.commit()