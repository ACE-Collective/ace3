from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from enum import Enum
import logging
import os
import socket
import threading
import time
from typing import Optional
from abc import ABC, abstractmethod
import uuid
from saq.analysis.root import Submission
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.group_configuration_loader import GroupConfigurationLoader
from saq.collectors.submission_scheduler import SubmissionScheduler
from saq.collectors.submission_file_manager import SubmissionFileManager
from saq.collectors.workload_repository import WorkloadRepository
from saq.collectors.duplicate_filter import DuplicateSubmissionFilter
from saq.configuration.config import get_config
from saq.constants import (
    NODE_STATUS_DRAINED,
    NODE_STATUS_DRAINING,
    NODE_STATUS_DRAINING_COLLECTORS,
    NODE_STATUS_RUNNING,
    NODE_STATUS_STOPPED,
)
from saq.database import remove_all_sessions
from saq.database.util.node import get_node_status_cached, update_collector_status
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.error import report_exception
from saq.logging import get_transaction_id, transaction_id
from saq.persistence import Persistable
from saq.service import ACEServiceInterface

# how often (in seconds) a collector service reports its status to the collector_status table
COLLECTOR_STATUS_REPORT_FREQUENCY = 5

# terminal outcomes of process_submission
# only SCHEDULED means the submission became real work; DUPLICATE is a drop
SUBMISSION_OUTCOME_SCHEDULED = "scheduled"
SUBMISSION_OUTCOME_DUPLICATE = "duplicate"

def get_collection_error_dir() -> str:
    return os.path.join(get_data_dir(), get_config().collection.error_dir)

class CollectorExecutionMode(Enum):
    """Enum representing the possible execution modes for a collector."""
    SINGLE_SHOT = "single_shot" # execute a single collection loop then exit
    SINGLE_SUBMISSION = "single_submission" # execute collection loop until one submission is processed
    CONTINUOUS = "continuous" # execute collection loop until shutdown event is set

class Collector(ABC):
    """Abstract base class for data collectors.
    
    Collectors are responsible for collecting data and yielding Submission objects.
    They should be focused solely on the collection logic and not concern themselves
    with service lifecycle, threading, database operations, or file management.
    """

    # set to True by collectors whose collect() returns a bounded batch rather than everything
    # available, so a pass that produced work is immediately followed by another pass instead of
    # waiting collection_frequency. a collector that drains its source in one call must leave this
    # False -- there is nothing left to collect when collect() returns, so looping straight back
    # around just re-hits the source
    collect_until_empty: bool = False

    def __init__(self):
        """Initialize the collector."""
        self.fqdn = socket.getfqdn()

    def update(self) -> None:
        """Called periodically while the collector is running. Execute any
        update routines required for the collector."""

    def cleanup(self) -> None:
        """Called after the collector has stopped."""
    
    @abstractmethod
    def collect(self) -> Generator[Submission, None, None]:
        """Returns a generator of Submission objects.
        
        This method should be implemented by subclasses to define their specific
        collection logic.
        
        Returns:
            Generator[Submission, None, None]: A generator of Submission objects.
        """
        ...


class CollectorService(ACEServiceInterface):
    """Service that hosts and manages a Collector instance.
    
    This class handles all the infrastructure concerns: service lifecycle,
    threading, database operations, file management, and submission scheduling.
    """
    
    def __init__(self, collector: Collector, config: CollectorServiceConfiguration):
        assert isinstance(collector, Collector)
        assert isinstance(config, CollectorServiceConfiguration)
        
        self.collector = collector
        self.config = config
        
        # the list of RemoteNodeGroup targets this collector will send to
        self.remote_node_groups = []
        
        # the directory that contains any files that to be transfered along with submissions
        self.incoming_dir = os.path.join(get_data_dir(), self.config.incoming_dir)
        
        # the directory that can contain various forms of persistence for collections
        self.persistence_dir = os.path.join(get_data_dir(), self.config.persistence_dir)

        # durable queue of submissions a collector has emitted but that have not been collected
        # yet, plus the scratch area they are built in. both live alongside incoming_dir so the
        # handoffs between them are atomic renames
        #
        # these are per-service, named after the collector's workload_type

        self.staging_dir = os.path.join(get_data_dir(), self.config.staging_dir or os.path.join(
            get_config().collection.staging_dir, self.config.workload_type))
        self.staging_tmp_dir = os.path.join(get_data_dir(), self.config.staging_tmp_dir or os.path.join(
            get_config().collection.staging_tmp_dir, self.config.workload_type))
        
        # primary collection thread that pulls Submission objects from the collector
        self.collection_thread = None
        
        # repeatedly calls execute_workload_cleanup
        self.cleanup_thread = None

        # shutdown control event
        self.shutdown_event = threading.Event()

        # these events are set once each one has started
        self.collect_started_event = threading.Event()
        self.update_started_event = threading.Event()
        self.cleanup_started_event = threading.Event()
        
        # persistence manager for this service
        self.persistence_manager = Persistable()
        
        # repository for database operations
        self.workload_repository = WorkloadRepository()
        self.workload_type_id = self.workload_repository.get_workload_type_id(self.config.workload_type)
        
        # file manager for file system operations
        self.file_manager = SubmissionFileManager(
            self.incoming_dir,
            self.persistence_dir,
            staging_dir=self.staging_dir,
            staging_tmp_dir=self.staging_tmp_dir,
            error_dir=get_collection_error_dir())
        
        # scheduler for handling submission orchestration
        self.submission_scheduler = None

        # initialize file system directories using the file manager
        self.file_manager.initialize_directories()
        
        # initialize persistence for this service
        self.persistence_manager.register_persistence_source(self.config.workload_type)
        
        # initialize the duplicate filter
        self.duplicate_filter = DuplicateSubmissionFilter(self.persistence_manager, self.config)
        
        # load the remote node groups if we haven't already
        #if not self.remote_node_groups:
            #self.load_groups()
        
        # make sure at least one is loaded
        #if not self.remote_node_groups:
            #raise RuntimeError("no RemoteNodeGroup objects have been added to {}".format(self))
        
        # initialize the submission scheduler
        self.submission_scheduler = SubmissionScheduler(
            self.workload_repository,
            self.file_manager,
            self.workload_type_id
        )

        # the execution mode for this collector service
        # defaults to normal operations (continuous)
        self.execution_mode: CollectorExecutionMode = CollectorExecutionMode.CONTINUOUS

        # when we next report our status to the collector_status table
        self.next_collector_status_report = None

        # set once we have logged that collection is paused so we don't log it every cycle
        self.collection_paused_logged = False

    def recover_staging(self):
        """Prepares the durable staging directory for collection.

        Anything left in the staging temp dir was mid-construction when the previous process
        died, so it is incomplete by definition and is dropped. Anything in the staging dir was
        emitted but never collected; it is replayed simply by being collected, so this only
        reports it. Must run before any collector begins producing.
        """
        self.file_manager.purge_incomplete_staging()

        staged_count = len(self.file_manager.list_staged_submissions())
        if staged_count:
            logging.info("recovered %d staged submissions from a previous run", staged_count)

        self.warn_about_legacy_staging()

    def warn_about_legacy_staging(self):
        """Reports submissions left behind by the version that shared one staging directory
        across every collector service.

        This is to support a smooth upgrade path from the version that shared one staging directory across every collector service.
        """
        legacy_dir = os.path.join(get_data_dir(), get_config().collection.staging_dir)
        try:
            orphans = [entry.name for entry in os.scandir(legacy_dir)
                       if entry.is_dir() and os.path.exists(os.path.join(entry.path, "data.json"))]
        except FileNotFoundError:
            return

        if orphans:
            logging.warning(
                "%d submissions are left in the shared staging directory %s from before "
                "collectors had their own queues - they will not be collected until they are "
                "moved into a per-collector staging directory",
                len(orphans), legacy_dir)

    def start(self, single_threaded: bool = False, execution_mode: CollectorExecutionMode = CollectorExecutionMode.CONTINUOUS):
        self.load_groups()

        if not self.remote_node_groups:
            raise RuntimeError("no RemoteNodeGroup objects have been added to {}".format(self))

        if single_threaded:
            self.start_single_threaded(execution_mode)
        else:
            self.recover_staging()
            self.start_multi_threaded(execution_mode)

    def start_single_threaded(self, execution_mode: CollectorExecutionMode=CollectorExecutionMode.SINGLE_SHOT, execute_nodes: bool=True):
        assert execution_mode in [CollectorExecutionMode.SINGLE_SHOT, CollectorExecutionMode.SINGLE_SUBMISSION], "invalid execution mode for single threaded collector"

        self.recover_staging()
        self.execution_mode = execution_mode
        self.update_loop()
        self.collection_loop()

        if execute_nodes:
            for group in self.remote_node_groups:
                group.loop(str(uuid.uuid4()), single_shot=True)

        self.execute_workload_cleanup()

    def start_multi_threaded(self, execution_mode: CollectorExecutionMode):
        self.execution_mode = execution_mode

        self.collection_thread = threading.Thread(target=self.collection_loop, name="Collector")
        self.collection_thread.start()

        self.update_thread = threading.Thread(target=self.update_loop, name="Collector Update")
        self.update_thread.start()
        
        self.cleanup_thread = threading.Thread(target=self.cleanup_loop, name="Collector Cleanup")
        self.cleanup_thread.start()
        
        # start the node groups
        for group in self.remote_node_groups:
            group.start()

    def wait_for_start(self, timeout: Optional[float] = None) -> bool:
        """Returns True if all threads have started, or False if any have not."""
        if not self.collect_started_event.wait(timeout):
            logging.error("collection thread did not start")
            return False

        if not self.update_started_event.wait(timeout):
            logging.error("update thread did not start")
            return False

        if not self.cleanup_started_event.wait(timeout):
            logging.error("cleanup thread did not start")
            return False

        return True

    def stop(self):
        self.shutdown_event.set()
        self.wait()

        # report that this collector has stopped
        # a stopped collector does not block a node drain
        try:
            self.report_collector_status(status=NODE_STATUS_STOPPED)
        except Exception as e:
            logging.error("unable to report collector status: %s", e)


    def wait(self):
        if self.collection_thread:
            logging.info("waiting for collection thread to terminate...")
            self.collection_thread.join()

        if self.update_thread:
            logging.info("waiting for update thread to terminate...")
            self.update_thread.join()
        
        for group in self.remote_node_groups:
            logging.info("waiting for {} thread to terminate...".format(group))
            group.wait()
        
        if self.cleanup_thread:
            logging.info("waiting for cleanup thread to terminate...")
            self.cleanup_thread.join()
        
        logging.info("collection ended")

    # group routines
    # ------------------------------------------------------------------------
    
    def create_group_loader(self) -> GroupConfigurationLoader:
        """Create a new GroupConfigurationLoader for the collector."""
        return GroupConfigurationLoader(
            self.workload_type_id,
            self.shutdown_event,
            self.workload_repository
        )
    
    def load_groups(self) -> bool:
        """If the remote node groups have not been loaded, load them from the ACE configuration file.
        Otherwise, do nothing.
        
        Returns:
            bool: True if the groups were loaded, False if they were already loaded.
        """
        if not self.remote_node_groups:
            self.remote_node_groups = self.create_group_loader().load_groups()
            return True

        return False

    # cleanup routines
    # ------------------------------------------------------------------------
    
    def cleanup_loop(self):
        logging.info(f"starting cleanup loop for {self} in {self.execution_mode} mode")

        self.cleanup_started_event.set()
        
        while not self.is_shutdown():
            try:
                self.execute_workload_cleanup()
            except Exception as e:
                logging.error(f"unable to execute workload cleanup: {e}")
                report_exception()

            if self.sleep(self.config.cleanup_frequency):
                break
        
        logging.info("exited cleanup loop")
    
    def execute_workload_cleanup(self):
        rows = self.workload_repository.get_completed_workloads(self.workload_type_id)
        submission_count = 0
        
        for work_id, root_uuid in rows:
            submission_count += 1

            # Use the file manager to delete the submission directory
            if self.file_manager.delete_submission_directory(root_uuid):
                # we finally clear the database entry for this workload item
                self.workload_repository.delete_workload(work_id)
                logging.info(f"completed work item {work_id}")
            else:
                logging.warning(f"failed to delete directory for work item {work_id}, keeping database entry")
        
        return submission_count

    # collection routines
    # ------------------------------------------------------------------------
    
    def collection_loop(self):
        """Primary loop for the collector."""

        logging.info(f"starting collection loop for {self} in {self.execution_mode} mode")

        self.shutdown_event.clear()
        self.collect_started_event.set()

        while not self.is_shutdown():
            try:
                # when the node is draining we stop collecting new work but keep the loop alive
                # the distribution and cleanup threads keep running to flush the backlog to other nodes
                # collection automatically resumes when the node returns to running
                if self.execution_mode == CollectorExecutionMode.CONTINUOUS and self.is_collection_paused():
                    if not self.collection_paused_logged:
                        logging.info("node is draining - pausing collection for %s", str(self))
                        self.collection_paused_logged = True

                    self.maybe_report_collector_status()
                    # a collector with a long collection_frequency would otherwise take that long
                    # to report the status the engine uses to decide the node has fully drained
                    self.sleep(min(self.config.collection_frequency, COLLECTOR_STATUS_REPORT_FREQUENCY))
                    continue

                if self.collection_paused_logged:
                    logging.info("node is no longer draining - resuming collection for %s", str(self))
                    self.collection_paused_logged = False

                self.maybe_report_collector_status()
                submission_count, scheduled_count = self.execute_collection_loop()

                if self.execution_mode == CollectorExecutionMode.SINGLE_SHOT:
                    self.shutdown_event.set()
                    break
                elif self.execution_mode == CollectorExecutionMode.SINGLE_SUBMISSION:
                    if submission_count > 0:
                        self.shutdown_event.set()
                        break

                # a collector that hands back everything it has in one call has nothing left to
                # collect the moment that call returns, so it always waits. only a collector that
                # returns a bounded batch loops straight back around, and only when the pass
                # actually produced work.
                #
                # this has to key off what was actually scheduled rather than what was yielded:
                # a collector whose source keeps re-serving the same items yields a nonzero count
                # every pass while every one of them is dropped as a duplicate, and keying off the
                # yielded count would spin this loop as fast as the source can answer
                if scheduled_count == 0 or not self.collect_until_empty:
                    self.sleep(self.config.collection_frequency)

            except Exception as e:
                logging.error(f"unexpected exception thrown during loop for {self}: {e}")
                report_exception()
                if self.sleep(1):
                    break
            finally:
                # this is a primary loop, so we need to release any database connections
                remove_all_sessions()
    
    def process_submission(self, submission: Submission) -> tuple[bool, str]:
        """Applies the duplicate filter to a single submission and schedules
        whatever survives. Returns (shutdown, outcome) where shutdown is True if the collector
        is shutting down and the caller should stop collecting, and outcome is one of the
        SUBMISSION_OUTCOME_* constants."""

        start_time = time.monotonic()
        duplicate_seconds = schedule_seconds = 0.0
        outcome = SUBMISSION_OUTCOME_SCHEDULED

        try:
            stage_time = time.monotonic()
            if submission.key:
                if self.duplicate_filter.is_duplicate(submission.key):
                    logging.info(f"skipping duplicate submission {submission.key}")
                    duplicate_seconds = time.monotonic() - stage_time
                    outcome = SUBMISSION_OUTCOME_DUPLICATE
                    self.file_manager.discard_staged_submission(submission.root.uuid)
                    return False, outcome

                logging.debug(f"marking submission {submission.key} as processed")
                self.duplicate_filter.mark_as_processed(submission.key)

            duplicate_seconds = time.monotonic() - stage_time

            stage_time = time.monotonic()
            if self.submission_scheduler:
                self.submission_scheduler.schedule_submission(submission, self.remote_node_groups)

            schedule_seconds = time.monotonic() - stage_time

        finally:
            total_seconds = time.monotonic() - start_time
            queue_age = submission.queue_age
            logging.info(
                "collected submission %s outcome=%s queue_age=%s duplicate=%.3fs "
                "schedule=%.3fs total=%.3fs",
                submission.root.uuid,
                outcome,
                "unknown" if queue_age is None else "%.1fs" % queue_age,
                duplicate_seconds,
                schedule_seconds,
                total_seconds,
            )

        return self.is_shutdown(), outcome

    def execute_collection_loop(self) -> tuple[int, int]:
        """Runs one full pass of the collector. Returns (submissions_processed,
        submissions_scheduled) -- everything the collector yielded, and the subset of that which
        actually became work. They differ whenever submissions are deduplicated."""
        submissions_processed = 0
        submissions_scheduled = 0

        try:
            # collect submissions from the collector
            for submission in self.collector.collect():
                submissions_processed += 1

                # whatever produced this submission recorded its transaction id on the root
                # (see RootAnalysis.transaction_id) -- adopt it so everything we log about
                # this submission correlates back to that hunt run, email, etc
                with transaction_id(submission.root.transaction_id or get_transaction_id()):
                    try:
                        shutdown, outcome = self.process_submission(submission)
                        if outcome == SUBMISSION_OUTCOME_SCHEDULED:
                            submissions_scheduled += 1

                        if shutdown:
                            break
                    except Exception as e:
                        # a staged submission stays on disk until it reaches a terminal outcome,
                        # so a submission that fails every time would be retried forever and,
                        # because one exception used to abandon the whole batch, would block
                        # everything queued behind it. quarantine it instead
                        logging.error("unable to process submission %s: %s", submission.root.uuid, e)
                        report_exception()
                        self.file_manager.quarantine_staged_submission(submission.root.uuid)

        except Exception as e:
            logging.error(f"error during collection: {e}")
            report_exception()

        # clear expired persistent data periodically
        self.clear_expired_persistent_data()
        return submissions_processed, submissions_scheduled

    # update routines
    # ------------------------------------------------------------------------
    
    def update_loop(self):
        """Loop for the collector update thread."""
        logging.info(f"starting update loop for {self}")

        self.update_started_event.set()
        
        while not self.is_shutdown():
            try:
                self.collector.update()
            except Exception as e:
                logging.error(f"error during update: {e}")
                report_exception()

            if self.execution_mode in [CollectorExecutionMode.SINGLE_SHOT, CollectorExecutionMode.SINGLE_SUBMISSION]:
                break

            if self.sleep(self.config.update_frequency):
                break
        
        logging.info("exited update loop")

    # node drain routines
    # ------------------------------------------------------------------------

    def is_collection_paused(self) -> bool:
        """Returns True if collection is paused because the node is draining.
        Note that only the draining statuses pause collection -- a collector can
        legitimately run on a node with no engine (status stopped)."""
        return get_node_status_cached() in [NODE_STATUS_DRAINING_COLLECTORS, NODE_STATUS_DRAINING, NODE_STATUS_DRAINED]

    def get_backlog_count(self) -> int:
        """Returns the number of work distribution entries this collector still needs to deliver."""
        return self.workload_repository.get_workload_backlog_count(self.workload_type_id)

    def report_collector_status(self, status: Optional[str]=None):
        """Reports the status of this collector service to the collector_status
        table in the central database. If status is not specified it is derived
        from the node status and the distribution backlog. The engine uses this
        to determine when a draining node has fully drained."""
        node_id = get_global_runtime_settings().saq_node_id
        if node_id is None:
            return

        backlog_count = self.get_backlog_count()
        if status is None:
            if self.is_collection_paused():
                status = NODE_STATUS_DRAINING if backlog_count else NODE_STATUS_DRAINED
            else:
                status = NODE_STATUS_RUNNING

        update_collector_status(node_id, self.config.workload_type, status, backlog_count)

    def maybe_report_collector_status(self):
        """Reports collector status if enough time has passed since the last report."""
        try:
            now = datetime.now(tz=timezone.utc)
            if self.next_collector_status_report is None or now >= self.next_collector_status_report:
                self.report_collector_status()
                self.next_collector_status_report = now + timedelta(seconds=COLLECTOR_STATUS_REPORT_FREQUENCY)
        except Exception as e:
            logging.error("unable to report collector status: %s", e)

    # utility routines
    # ------------------------------------------------------------------------

    def clear_expired_persistent_data(self):
        if self.duplicate_filter:
            self.duplicate_filter.clear_expired_data()

    @property
    def collect_until_empty(self) -> bool:
        """True if a collection pass that scheduled work should immediately run another pass
        instead of waiting collection_frequency. The collector class declares whether it returns
        a bounded batch; the service config can override that either way.

        Resolved on every access rather than cached at construction because the collector this
        service hosts can be replaced after __init__ (see HunterService)."""
        if self.config.collect_until_empty is not None:
            return self.config.collect_until_empty

        return self.collector.collect_until_empty

    def sleep(self, time: float) -> bool:
        """Waits for the specified time or until the shutdown event is set.
        Returns True if the shutdown event is set."""
        return self.shutdown_event.wait(time)

    def is_shutdown(self) -> bool:
        """Returns True if the collector is shutting down."""
        return self.shutdown_event.is_set()