    
from datetime import datetime
import logging
import os
import shutil
import threading
from typing import Optional, Union
import uuid

import requests
import urllib3

from ace_api import upload
from saq.analysis.root import RootAnalysis, Submission
from saq.configuration.config import get_config, get_engine_config
from saq.constants import ANALYSIS_MODE_CORRELATION, DB_COLLECTION, NO_NODES_AVAILABLE, NO_WORK_AVAILABLE, NO_WORK_SUBMITTED, WORK_SUBMITTED
from saq.database import ALERT, execute_with_retry, get_db, get_db_connection
from saq.database.pool import execute_with_db_cursor
from saq.engine.node_manager.distributed_node_manager import translate_node
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.error import report_exception
from saq.util.uuid import storage_dir_from_uuid


class RemoteNode:
    """Represents a remote Engine node."""
    def __init__(
            self, 
            id: int, 
            name: str, 
            location: str, 
            any_mode: int, 
            last_update: datetime, 
            analysis_mode: Union[str, None], 
            workload_count: int, 
            company_id: Optional[int]=None):

        assert isinstance(id, int)
        assert isinstance(name, str)
        assert isinstance(location, str)
        assert isinstance(any_mode, int)
        assert isinstance(last_update, datetime)
        assert analysis_mode is None or isinstance(analysis_mode, str)
        assert isinstance(workload_count, int)

        self.id: int = id
        self.name: str = name
        self.location: str = translate_node(location)
        self.any_mode: int = any_mode
        self.last_update: datetime = last_update
        self.analysis_mode: str = analysis_mode
        self.workload_count: int = workload_count
        self.company_id: Optional[int] = company_id

        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(get_data_dir(), get_config().collection.incoming_dir)

    def __str__(self):
        return "RemoteNode(id={},name={},location={})".format(self.id, self.name, self.location)

    @property
    def is_local(self) -> bool:
        """Returns True if this RemoteNode refers to the local node."""
        return self.name == get_global_runtime_settings().saq_node 

    def submit(self, submission: Submission):
        assert isinstance(submission, Submission)

        # if we are submitting locally then we can bypass the API layer
        if self.is_local and not get_config().collection.force_api:
            return self.submit_local(submission)
        else:
            return self.submit_remote(submission)

    def submit_local(self, submission):
        """Attempts to submit the given the local engine node."""
        logging.debug(f"submitting {submission} locally")

        # we duplicate because we could be sending multiple copies to multiple remote nodes
        new_root = submission.root.duplicate()
        new_root.move(storage_dir_from_uuid(new_root.uuid))
        new_root.save()

        # if we received a submission for correlation mode then we go ahead and add it to the database
        if new_root.analysis_mode == ANALYSIS_MODE_CORRELATION:
            ALERT(new_root)

        new_root.schedule()

        # XXX what is with this return value?
        return { 'result': new_root.uuid }

    def submit_remote(self, submission: Submission) -> str:
        """Attempts to submit the given remote Submission to this node."""
        try:
            # we need to convert the list of files to what is expected by the ace_api.submit function
            logging.debug(f"submitting {submission} remotely")

            temp_root = submission.root.duplicate()

            result = upload(
                temp_root.uuid,
                temp_root.storage_dir,
                is_alert=False, # uploading a non-alet
                overwrite=False, # would not make sense
                sync=True, # ends up calling root.schedule() on the other side
                move=False, # not an Alert yet
                remote_host=self.location, # should be sent to this node
                ssl_verification=get_config().SSL.ca_chain_path,
            )

            result = result['result']
            logging.info("submit remote {} submission {} uuid {}".format(self.location, submission, temp_root.uuid))
            return temp_root.uuid

        except Exception as e:
            logging.warning("submission irregularity for {}: {} ({})".format(submission, e, type(e)))
            report_exception()
            raise e

        finally:
            shutil.rmtree(temp_root.storage_dir, ignore_errors=True)

class RemoteNodeGroup:
    """Represents a collection of one or more RemoteNode objects that share the
       same group configuration property."""

    def __init__(
            self,
            name: str,
            coverage: int,
            full_delivery: bool,
            company_id: int,
            database: str,
            group_id: int,
            workload_type_id: int,
            shutdown_event: threading.Event,
            batch_size: Optional[int]=32,
            target_node_as_company_id: Optional[int]=None,
            target_nodes: Optional[list]=None,
            thread_count: Optional[int]=1):

        assert isinstance(name, str) and name
        assert isinstance(coverage, int) and coverage > 0 and coverage <= 100
        assert isinstance(full_delivery, bool)
        assert isinstance(company_id, int)
        assert isinstance(database, str)
        assert isinstance(group_id, int)
        assert isinstance(workload_type_id, int)
        assert isinstance(shutdown_event, threading.Event)
        assert target_nodes is None or isinstance(target_nodes, list)
        assert isinstance(thread_count, int)

        self.name = name

        # this the percentage of submissions that are actually sent to this node group
        self.coverage = coverage
        self.coverage_counter = 0

        # if full_delivery is True then all submissions assigned to the group will eventually be submitted
        # if set to False then at least one attempt is made to submit
        # setting to False is useful for QA and development type systems
        self.full_delivery = full_delivery

        # the company this node group belongs to
        self.company_id = company_id

        # A company id for the primary node sharing this company data
        self.target_node_as_company_id = target_node_as_company_id

        # the name of the database to query for node status
        self.database = database

        # the id of this group in the work_distribution_groups table
        self.group_id = group_id

        # the type of work that this collector works with
        self.workload_type_id = workload_type_id

        # the (maximum) number of work items to pull at once from the database
        self.batch_size = batch_size

        # metrics
        self.assigned_count = 0 # how many emails were assigned to this group
        self.skipped_count = 0 # how many emails have skipped due to coverage rules
        self.delivery_failures = 0 # how many emails failed to delivery when full_delivery is disabled

        # total number of threads to run for submission
        self.thread_count = thread_count
        # main threads of execution for this group
        self.threads = []

        # reference to Controller.shutdown_event, used to synchronize a clean shutdown
        self.shutdown_event = shutdown_event

        # an optional list of target nodes names this group will limit itself to
        # if this list is empty then there is no limit
        self.target_nodes = target_nodes
        if self.target_nodes is None:
            self.target_nodes = []

        # when do we think a node has gone offline
        # each node (engine) should update it's status every [engine][node_status_update_frequency] seconds
        # so we wait for twice that long until we think a node is offline
        # at which point we no longer consider it for submissions
        self.node_status_update_frequency = get_engine_config().node_status_update_frequency

        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(get_data_dir(), get_config().collection.incoming_dir)
        
        # sync lock for assigning work to the threads
        self.work_sync_lock = threading.RLock()

    def start(self):
        self.shutdown_event.clear()
        self.clear_work_locks()

        # main threads of execution for this group
        for index in range(self.thread_count):
            thread = threading.Thread(target=self.loop, args=(str(uuid.uuid4()),), name=f"RemoteNodeGroup {self.name} - {index}")
            thread.start()
            self.threads.append(thread)

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        for thread in self.threads:
            logging.debug(f"waiting for {thread} to complete")
            thread.join()

        self.threads = []

    def loop(self, work_lock_uuid: str, single_shot: bool = False):
        logging.info(f"starting remote node group loop ({work_lock_uuid})")
        while True:
            try:
                result = execute_with_db_cursor(DB_COLLECTION, self.execute, work_lock_uuid)
                log_func = logging.info
                if result == NO_WORK_AVAILABLE:
                    log_func = logging.debug
                log_func(f"remote node group loop result ({result})")
                if single_shot:
                    break

                # if we did something then we immediately look for more work unless we're shutting down
                if result == WORK_SUBMITTED:
                    if self.shutdown_event.is_set():
                        break
                # if were was no work available to be submitted then wait a second and look again
                elif result == NO_WORK_AVAILABLE:
                    if self.shutdown_event.wait(1):
                        break
                # if there were no NODES available then wait a little while longer and look again
                elif result == NO_NODES_AVAILABLE:
                    if self.shutdown_event.wait(self.node_status_update_frequency / 2):
                        break
                elif result == NO_WORK_SUBMITTED:
                    if self.shutdown_event.wait(1):
                        break

            except Exception as e:
                logging.error("unexpected exception thrown in loop for {}: {}".format(self, e))
                report_exception()
                if self.shutdown_event.wait(1):
                    break

            finally:
                get_db().remove()

    def release_work_locks(self):
        with get_db_connection(DB_COLLECTION) as db:
            cursor = db.cursor()
            cursor.execute("""
            UPDATE work_distribution SET 
                status = 'READY', 
                lock_uuid = NULL, 
                lock_time = NULL 
            WHERE 
                status = 'LOCKED' AND group_id = %s
            """, (self.group_id,))
            db.commit()

    def execute(self, db, cursor, work_lock_uuid):
        # first we get a list of all the distinct analysis modes available in the work queue
        cursor.execute("""
SELECT DISTINCT(incoming_workload.mode)
FROM
    incoming_workload JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
WHERE
    incoming_workload.type_id = %s
    AND work_distribution.group_id = %s
    AND work_distribution.status IN ( 'READY', 'LOCKED' )
""", (self.workload_type_id, self.group_id,))
        available_modes = cursor.fetchall()
        db.commit()

        # if we get nothing from this query then no work is available for this group
        if not available_modes:
            if get_global_runtime_settings().unit_testing:
                logging.debug("no work available for {}".format(self))
            return NO_WORK_AVAILABLE

        # flatten this out to a list of analysis modes
        available_modes = [_[0] for _ in available_modes]

        # given this list of modes that need remote targets, see what is currently available
        with get_db_connection(self.database) as node_db:
            node_cursor = node_db.cursor()

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
    LEFT JOIN node_modes_excluded ON nodes.id = node_modes_excluded.node_id
    LEFT JOIN workload ON nodes.id = workload.node_id
WHERE
    {where_clause}
GROUP BY
    nodes.id,
    nodes.name,
    nodes.location,
    nodes.any_mode,
    nodes.last_update,
    node_modes.analysis_mode,
    node_modes_excluded.analysis_mode
ORDER BY
    WORKLOAD_COUNT ASC,
    nodes.last_update ASC
"""
            where_clause = []
            where_clause_params = []

            # XXX not sure what this does
            company_id = self.company_id
            if self.target_node_as_company_id is not None:
                company_id = self.target_node_as_company_id

            where_clause.append("nodes.company_id = %s")
            where_clause_params.append(company_id)

            where_clause.append("TIMESTAMPDIFF(SECOND, nodes.last_update, NOW()) <= %s")
            where_clause_params.append(self.node_status_update_frequency * 2)

            param_str = ','.join(['%s' for _ in available_modes])
            where_clause.append(f""" 
            (
                (nodes.any_mode AND 
                    (node_modes_excluded.analysis_mode IS NULL 
                     OR node_modes_excluded.analysis_mode NOT IN ( {param_str} )
                    )
                )
                OR node_modes.analysis_mode IN ( {param_str} )
            ) """)
            where_clause_params.extend(available_modes)
            where_clause_params.extend(available_modes)

            # are we limiting what nodes we are sending to?
            if self.target_nodes:
                param_str = ','.join(['%s' for _ in self.target_nodes])
                where_clause.append(f"nodes.name IN ( {param_str} )")
                where_clause_params.extend(self.target_nodes)

            sql = sql.format(where_clause='AND '.join([f'( {_} ) ' for _ in where_clause]))
            node_cursor.execute(sql, tuple(where_clause_params))
            node_status = node_cursor.fetchall()

        if not node_status:
            logging.warning("no remote nodes are avaiable for all analysis modes {} for {}".format(
                            ','.join(available_modes), self))

            if not self.full_delivery:
                # if this node group is NOT in full_delivery mode and there are no nodes available at all
                # then we just clear out the work queue for this group
                # if this isn't done then the work will pile up waiting for a node to come online
                execute_with_retry(db, cursor, "UPDATE work_distribution SET status = 'ERROR' WHERE group_id = %s",
                                  (self.group_id,), commit=True)

            return NO_NODES_AVAILABLE

        # now figure out what analysis modes are actually available for processing
        analysis_mode_mapping = {} # key = analysis_mode, value = [ RemoteNode ]
        any_mode_nodes = [] # list of nodes with any_mode set to True
        
        for node_id, name, location, any_mode, last_update, analysis_mode, workload_count in node_status:
            remote_node = RemoteNode(node_id, name, location, any_mode, last_update, analysis_mode, workload_count, company_id=self.company_id)
            if any_mode:
                any_mode_nodes.append(remote_node)

            if analysis_mode:
                if analysis_mode not in analysis_mode_mapping:
                    analysis_mode_mapping[analysis_mode] = []

                analysis_mode_mapping[analysis_mode].append(remote_node)

        # now we trim our list of analysis modes down to what is available
        # if we don't have a node that supports any mode
        if not any_mode_nodes:
            available_modes = [m for m in available_modes if m in analysis_mode_mapping.keys()]
            logging.debug("available_modes = {} after checking available nodes".format(available_modes))

        if not available_modes:
            logging.debug("no nodes are available that support the available analysis modes")
            return NO_NODES_AVAILABLE

        # do we have anything locked yet?
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE lock_uuid = %s AND status IN ( 'READY', 'LOCKED' )", (work_lock_uuid,))
        result = cursor.fetchone()
        lock_count = result[0]

        if lock_count > 0:
            logging.debug(f"already have {lock_count} work items locked by {work_lock_uuid}")

        # if we don't have any locks yet, go make some
        if lock_count == 0:
            sql = """
UPDATE work_distribution
SET
    status = 'LOCKED',
    lock_time = NOW(),
    lock_uuid = %s
WHERE 
    group_id = %s
    AND work_id IN ( SELECT * FROM ( 
        SELECT
            incoming_workload.id
        FROM
            incoming_workload JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
        WHERE
            incoming_workload.type_id = %s
            AND work_distribution.group_id = %s
            AND incoming_workload.mode IN ( {} )
            AND (
                work_distribution.status = 'READY'
                OR ( work_distribution.status = 'LOCKED' AND TIMESTAMPDIFF(minute, work_distribution.lock_time, NOW()) >= 10 )
            )
        ORDER BY
            incoming_workload.id ASC
        LIMIT %s ) AS t1 )
""".format(','.join(['%s' for _ in available_modes]))
            params = [ work_lock_uuid, self.group_id, self.workload_type_id, self.group_id ]
            params.extend(available_modes)
            params.append(self.batch_size)

            with self.work_sync_lock:
                execute_with_retry(db, cursor, sql, tuple(params), commit=True)

        # now we get the next things to submit from the database that have an analysis mode that is currently
        # available to be submitted to

        sql = """
SELECT 
    incoming_workload.id,
    incoming_workload.mode,
    incoming_workload.work
FROM
    incoming_workload JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
WHERE
    work_distribution.lock_uuid = %s AND work_distribution.status = 'LOCKED'
ORDER BY
    incoming_workload.id ASC
"""
        params = [ work_lock_uuid ]
        cursor.execute(sql, tuple(params))
        work_batch = cursor.fetchall()
        db.commit()

        if len(work_batch) > 0:
            logging.info("submitting {} items".format(len(work_batch)))

        # simple flag that gets set if ANY submission is successful
        submission_success = False

        # we should have a small list of things to submit to remote nodes for this group
        for work_id, analysis_mode, root_uuid in work_batch:
            logging.info(f"preparing workload {work_id} with uuid {root_uuid}")

            # first make sure we can load this
            # XXX not sure we really need to do this
            try:
                root = RootAnalysis(storage_dir=os.path.join(self.incoming_dir, root_uuid))
                root.load()
                submission = Submission(root)
            except Exception as e:
                execute_with_retry(db, cursor, """UPDATE work_distribution SET status = 'ERROR' 
                                             WHERE group_id = %s AND work_id = %s""",
                                  (self.group_id, work_id), commit=True)
                logging.error("unable to load submission root for id {} uuid {}: {}".format(work_id, root_uuid, e))
                continue

            # simple flag to remember if we failed to send
            submission_failed = False

            # the result of the submission (we pass to Submission.success later)
            submission_result = None
                
            self.coverage_counter += self.coverage
            if self.coverage_counter < 100:
                # we'll be skipping this one
                logging.debug("skipping work id {} for group {} due to coverage constraints".format(
                              work_id, self.name))
            else:
                # otherwise we try to submit it
                self.coverage_counter -= 100

                # sort the list of RemoteNode objects by the workload_count
                available_targets = any_mode_nodes[:]
                if analysis_mode in analysis_mode_mapping:
                    available_targets.extend(analysis_mode_mapping[analysis_mode])
            
                target = sorted(available_targets, key=lambda n: n.workload_count)
                target = target[0] 

                # attempt the send
                try:
                    submission_result = target.submit(submission)
                    logging.info("{} got submission result {} for {}".format(self, submission_result, submission))
                    submission_success = True
                except Exception as e:
                    if self.full_delivery:
                        if not isinstance(e, urllib3.exceptions.MaxRetryError) \
                                and not isinstance(e, urllib3.exceptions.NewConnectionError) \
                                and not isinstance(e, requests.exceptions.ConnectionError):
                            # if it's not a connection issue then report it
                            report_exception()

                    logging.warning("unable to submit work item {} to {} via group {}: {}".format(
                            submission, target, self, e))
                    report_exception()

                    # if we are in full delivery mode then we need to try this one again later
                    if self.full_delivery and (isinstance(e, urllib3.exceptions.MaxRetryError) \
                                               or isinstance(e, urllib3.exceptions.NewConnectionError) \
                                               or isinstance(e, requests.exceptions.ConnectionError) \
                                               or isinstance(e, requests.exceptions.HTTPError)):
                        continue

                    # otherwise we consider it a failure
                    submission_failed = True
                    execute_with_retry(db, cursor, """UPDATE work_distribution SET status = 'ERROR' 
                                                 WHERE group_id = %s AND work_id = %s""",
                                       (self.group_id, work_id), commit=True)
            
            # if we skipped it or we sent it, then we're done with it
            if not submission_failed:
                execute_with_retry(db, cursor, """UPDATE work_distribution SET status = 'COMPLETED' 
                                             WHERE group_id = %s AND work_id = %s""",
                                  (self.group_id, work_id), commit=True)

        if submission_success:
            return WORK_SUBMITTED

        return NO_WORK_SUBMITTED

    def clear_work_locks(self):
        """Clears any work locks set with work assigned to this group."""
        with get_db_connection(DB_COLLECTION) as db:
            cursor = db.cursor()
            cursor.execute("""
            UPDATE work_distribution SET 
                status = 'READY', 
                lock_uuid = NULL, 
                lock_time = NULL 
            WHERE 
                status = 'LOCKED' AND group_id = %s
            """, (self.group_id,))
            db.commit()

    def __str__(self):
        return "RemoteNodeGroup(name={}, coverage={}, full_delivery={}, company_id={}, database={})".format(
                self.name, self.coverage, self.full_delivery, self.company_id, self.database)

def save_submission_for_review(submission: Submission):
    """Saves the given submission to data/var/collectors/error/{uuid} using pickle."""
    from saq.collectors.base_collector import get_collection_error_dir
    error_dir = os.path.join(get_collection_error_dir(), submission.root.uuid)
    submission.root.move(error_dir)
    logging.warning(f"dumped submission to {error_dir} for review")