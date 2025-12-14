import logging
import os
import shutil
from typing import Optional

from saq.analysis.root import RootAnalysis
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.database.util.workload import add_workload
from saq.database.util.delayed_analysis import add_delayed_analysis_request as db_add_delayed_analysis_request, clear_delayed_analysis_requests as db_clear_delayed_analysis_requests
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.lock_manager.interface import LockManagerInterface
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.workload_manager.interface import WorkloadManagerInterface
from saq.environment import get_global_runtime_settings
from saq.error import report_exception
from saq.util import storage_dir_from_uuid


class DatabaseWorkloadManager(WorkloadManagerInterface):
    """Manages workload and queue operations for the analysis engine."""
    
    def __init__(
        self,
        lock_manager: LockManagerInterface,
        configuration_manager: ConfigurationManager,
        node_manager: NodeManagerInterface,
        analysis_mode_priority: Optional[str] = None,
    ):
        """Initialize the WorkloadManager.
        
        Args:
            configuration_manager: ConfigurationManager instance for loading configuration
            node_manager: NodeManager instance for loading node configuration
            lock_manager: Distributed lock manager for acquiring/releasing work item locks
            analysis_mode_priority: Primary analysis mode for this worker
        """
        self.configuration_manager = configuration_manager
        self.config = configuration_manager.config
        self.node_manager = node_manager
        self.lock_manager = lock_manager
        self.analysis_mode_priority = analysis_mode_priority

    @property
    def local_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine supports."""
        return self.config.local_analysis_modes
    
    @property
    def excluded_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine excludes."""
        return self.config.excluded_analysis_modes

    @property
    def target_nodes(self) -> list[str]:
        """List of nodes this engine will pull work from."""
        return self.node_manager.target_nodes

    @property
    def delayed_analysis_queue_size(self) -> int:
        """Returns the size of the delayed analysis queue (for this engine.)"""
        with get_db_connection() as db:
            c = db.cursor()
            where_clause = ["node_id = %s"]
            params = [get_global_runtime_settings().saq_node_id]

            where_clause = " AND ".join(where_clause)
            params = tuple(params)

            c.execute(
                "SELECT COUNT(*) FROM delayed_analysis WHERE {}".format(where_clause),
                params,
            )
            row = c.fetchone()
            return row[0]

    @property
    def workload_queue_size(self) -> int:
        """Returns the size of the workload queue (for this node.)"""
        with get_db_connection() as db:
            c = db.cursor()
            where_clause = ["node_id = %s"]
            params = [get_global_runtime_settings().saq_node_id]

            where_clause.append("company_id = %s")
            params.append(get_global_runtime_settings().company_id)

            if self.local_analysis_modes:
                where_clause.append(
                    "workload.analysis_mode IN ( {} )".format(
                        ",".join(["%s" for _ in self.local_analysis_modes])
                    )
                )
                params.extend(self.local_analysis_modes)

            where_clause = " AND ".join(where_clause)
            params = tuple(params)

            c.execute(
                "SELECT COUNT(*) FROM workload WHERE {}".format(where_clause), params
            )
            row = c.fetchone()
            return row[0]

    @property
    def delayed_analysis_queue_is_empty(self) -> bool:
        """Returns True if the delayed analysis queue is empty, False otherwise."""
        return self.delayed_analysis_queue_size == 0

    @property
    def workload_queue_is_empty(self) -> bool:
        """Returns True if the work queue is empty, False otherwise."""
        return self.workload_queue_size == 0

    def add_workload(self, root: RootAnalysis) -> None:
        """Add a RootAnalysis to the workload queue."""
        assert isinstance(root, RootAnalysis)
        return add_workload(root)

    def transfer_work_target(self, uuid: str, node_id: int) -> Optional[RootAnalysis]:
        """Moves the given work target from the given remote node to the local node.
        Returns the (unloaded) RootAnalysis for the object transferred."""
        from ace_api import download, clear

        logging.info("downloading work target {} from {}".format(uuid, node_id))

        # get a lock on the target we want to transfer
        if not self.lock_manager.acquire_lock(uuid):
            logging.info("unable to acquire lock on {} for transfer".format(uuid))
            return False

        # XXX get the storage directory from the database
        target_dir = storage_dir_from_uuid(uuid)
        if os.path.isdir(target_dir):
            logging.warning(
                "target_dir {} for transfer exists! bailing...".format(target_dir)
            )
            return False

        try:
            logging.debug("creating transfer target_dir {}".format(target_dir))
            os.makedirs(target_dir)
        except Exception as e:
            logging.error(
                "unable to create transfer target_dir {}: {}".format(target_dir, e)
            )
            report_exception()
            return False

        tar_path = None

        try:
            # now make the transfer
            # look up the url for this target node
            with get_db_connection() as db:
                c = db.cursor()
                c.execute("SELECT location FROM nodes WHERE id = %s", (node_id,))
                row = c.fetchone()
                if row is None:
                    logging.error(
                        "cannot find node_id {} in nodes table".format(node_id)
                    )
                    return False

                remote_host = row[0]
                download(uuid, target_dir, remote_host=remote_host)

                # update the node (location) of this workitem to the local node
                execute_with_retry(
                    db,
                    c,
                    "UPDATE workload SET node_id = %s, storage_dir = %s WHERE uuid = %s",
                    (get_global_runtime_settings().saq_node_id, target_dir, uuid),
                )
                execute_with_retry(
                    db,
                    c,
                    "UPDATE delayed_analysis SET node_id = %s, storage_dir = %s WHERE uuid = %s",
                    (get_global_runtime_settings().saq_node_id, target_dir, uuid),
                )
                execute_with_retry(
                    db,
                    c,
                    "UPDATE alerts SET location = %s, storage_dir = %s WHERE uuid = %s",
                    (get_global_runtime_settings().saq_node, target_dir, uuid),
                )
                db.commit()

                # then finally tell the remote system to clear this work item
                # we use our lock uuid as kind of password for clearing the work item
                clear(uuid, self.lock_manager.lock_uuid, remote_host=remote_host)

                # load the analysis we moved over and change the location there as well
                root = RootAnalysis(storage_dir=target_dir)
                root.load()
                root.location = get_global_runtime_settings().saq_node
                root.save()

                return RootAnalysis(uuid=uuid, storage_dir=target_dir)

        except Exception as e:
            logging.error("unable to transfer {}: {}".format(uuid, e))
            report_exception()
            try:
                shutil.rmtree(target_dir)
            except Exception as e:
                logging.error(
                    "unable to clear transfer target_dir {}: {}".format(target_dir, e)
                )
                report_exception()

            return None

        finally:
            try:
                if tar_path:
                    os.remove(tar_path)
            except Exception as e:
                logging.error(
                    "unable to delete temporary tar file {}: {}".format(tar_path, e)
                )
                report_exception()

    def get_delayed_analysis_work_target(self) -> Optional[DelayedAnalysisRequest]:
        """Returns the next DelayedAnalysisRequest that is ready, or None if none are ready."""
        # get the next thing to do
        # first we look for any delayed analysis that needs to complete

        sql = """
SELECT 
    delayed_analysis.id, 
    delayed_analysis.uuid, 
    delayed_analysis.observable_uuid, 
    delayed_analysis.analysis_module, 
    delayed_analysis.delayed_until,
    delayed_analysis.storage_dir
FROM
    delayed_analysis LEFT JOIN locks ON delayed_analysis.uuid = locks.uuid
WHERE
    delayed_analysis.node_id = %s
    AND locks.uuid IS NULL
    AND NOW() >= delayed_until
ORDER BY
    delayed_until ASC
"""

        params = [get_global_runtime_settings().saq_node_id]

        with get_db_connection() as db:
            c = db.cursor()
            c.execute(sql, tuple(params))

            for (
                _id,
                uuid,
                observable_uuid,
                analysis_module,
                delayed_until,
                storage_dir,
            ) in c:
                if not self.lock_manager.acquire_lock(uuid):
                    continue

                return DelayedAnalysisRequest(
                    uuid,
                    observable_uuid,
                    analysis_module,
                    delayed_until,
                    storage_dir,
                    database_id=_id,
                )

        return None

    def get_work_target(self, priority: bool = True, local: bool = True) -> Optional[RootAnalysis]:
        """Returns the next work item available.
        
        Args:
            priority: If True, only work items with analysis_modes that match the analysis_mode_priority
            local: If True, only work items on the local node are selected. Remote work items are moved to become local.
            
        Returns:
            A valid work item, or None if none are available.
        """
        with get_db_connection() as db:
            cursor = db.cursor()

            where_clause = ["locks.uuid IS NULL"]
            params = []

            if self.analysis_mode_priority and priority:
                where_clause.append("workload.analysis_mode = %s")
                params.append(self.analysis_mode_priority)

            if local:
                where_clause.append("workload.node_id = %s")
                params.append(get_global_runtime_settings().saq_node_id)
            else:
                # if we're looking remotely then we need to make sure we only select work for whatever company
                # this node belongs to
                # this is true for instances where you're sharing an ACE resource between multiple companies
                where_clause.append("workload.company_id = %s")
                params.append(get_global_runtime_settings().company_id)

            if self.local_analysis_modes:
                # limit our scope to locally support analysis modes
                where_clause.append(
                    "workload.analysis_mode IN ( {} )".format(
                        ",".join(["%s" for _ in self.local_analysis_modes])
                    )
                )
                params.extend(self.local_analysis_modes)
            elif self.excluded_analysis_modes:
                where_clause.append(
                    "workload.analysis_mode NOT IN ( {} )".format(
                        ",".join(["%s" for _ in self.excluded_analysis_modes])
                    )
                )
                params.extend(self.excluded_analysis_modes)

            # are we limiting what nodes we pull work from?
            if self.target_nodes:
                param_str = ",".join(["%s" for _ in self.target_nodes])
                where_clause.append(
                    f"workload.node_id IN ( SELECT id FROM nodes WHERE name IN ( {param_str} ) )"
                )
                params.extend(self.target_nodes)

            where_clause = " AND ".join(
                ["({})".format(clause) for clause in where_clause]
            )

            if get_global_runtime_settings().unit_testing:
                logging.debug(
                    "looking for work with {} ({})".format(
                        where_clause, ",".join([str(_) for _ in params])
                    )
                )

            cursor.execute(
                """
SELECT
    workload.id,
    workload.uuid,
    workload.analysis_mode,
    workload.insert_date,
    workload.node_id,
    workload.storage_dir,
    RAND() as "random_sort"
FROM
    workload LEFT JOIN locks ON workload.uuid = locks.uuid
WHERE
    {where_clause}
ORDER BY
    random_sort
LIMIT 128""".format(
                    where_clause=where_clause
                ),
                tuple(params),
            )

            for (
                _id,
                uuid,
                analysis_mode,
                insert_date,
                node_id,
                storage_dir,
                _,
            ) in cursor:
                if not self.lock_manager.acquire_lock(uuid):
                    continue

                # after we acquire the lock we need to make sure that the workload item is still present
                # this can happen because the listing of the available workload items and the acquiring of the lock
                # is a two-step process -- they can be completed and cleared in between those two steps

                c2 = db.cursor()
                c2.execute("SELECT uuid FROM workload WHERE id = %s", _id)
                verify = c2.fetchone()
                if not verify:
                    logging.info(
                        f"workload item {_id} for {uuid} was already processed"
                    )
                    self.lock_manager.release_lock(uuid)
                    continue

                # is this work item on a different node?
                if node_id != get_global_runtime_settings().saq_node_id:
                    # go grab it
                    return self.transfer_work_target(uuid, node_id)

                logging.info(
                    f"got workload item {_id} uuid {uuid} for analysis mode {analysis_mode} with lock {self.lock_manager.lock_uuid}"
                )
                return RootAnalysis(
                    uuid=uuid, storage_dir=storage_dir, analysis_mode=analysis_mode
                )

            return None

    def get_next_work_target(self):
        """Get the next available work target using priority and locality preferences."""
        try:
            # get any delayed analysis work that is ready to be processed
            target = self.get_delayed_analysis_work_target()
            if target:
                return target

            if self.analysis_mode_priority:
                # get any local work with high priority
                target = self.get_work_target(priority=True, local=True)
                if target:
                    return target

                # get any work with high priority
                target = self.get_work_target(priority=True, local=False)
                if target:
                    return target

            # get any available local work
            target = self.get_work_target(priority=False, local=True)
            if target:
                return target

            # get any available work
            target = self.get_work_target(priority=False, local=False)
            if target:
                return target

        except Exception as e:
            logging.error("unable to get work target: {}".format(e))
            report_exception()

        # no work available anywhere
        return None

    def clear_work_target(self, target):
        """Clear a work target from the database and release its lock.
        
        Args:
            target: The work target to clear (RootAnalysis or DelayedAnalysisRequest)
        """
        try:
            with get_db_connection() as db:
                c = db.cursor()
                if isinstance(target, DelayedAnalysisRequest):
                    execute_with_retry(
                        db,
                        c,
                        "DELETE FROM delayed_analysis WHERE id = %s",
                        (target.database_id,),
                    )
                else:
                    execute_with_retry(
                        db,
                        c,
                        "DELETE FROM workload WHERE uuid = %s AND analysis_mode = %s",
                        (target.uuid, target.original_analysis_mode),
                    )

                db.commit()

                # this is more of a fail-safe so we ignore the lock failure if it's already been released
                self.lock_manager.release_lock(target.uuid, ignore_lock_failure=True)
                    
                logging.debug(f"cleared work target {target}")

        except Exception as e:
            logging.error(f"unable to clear work target {target}: {e}")
            report_exception()

    def add_delayed_analysis_request(self, root, observable, analysis_module, hours, minutes, seconds):
        """Add a delayed analysis request."""
        return db_add_delayed_analysis_request(
            root, 
            observable, 
            analysis_module, 
            hours, 
            minutes, 
            seconds, 
        )

    def clear_delayed_analysis_requests(self, root):
        """Clear all delayed analysis requests for the given RootAnalysis object."""
        return db_clear_delayed_analysis_requests(root)