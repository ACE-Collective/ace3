from enum import Enum
import logging
import os
import socket
import threading
from typing import Generator, Optional
from abc import ABC, abstractmethod
import uuid
from saq.analysis.root import Submission
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.group_configuration_loader import GroupConfigurationLoader
from saq.collectors.submission_scheduler import SubmissionScheduler
from saq.collectors.submission_file_manager import SubmissionFileManager
from saq.collectors.workload_repository import WorkloadRepository
from saq.collectors.duplicate_filter import DuplicateSubmissionFilter
from saq.configuration import get_config_value
from saq.constants import CONFIG_COLLECTION, CONFIG_COLLECTION_ERROR_DIR
from saq.database import get_db
from saq.environment import get_data_dir
from saq.error import report_exception
from saq.persistence import Persistable
from saq.service import ACEServiceInterface
from saq.submission_filter import SubmissionFilter

def get_collection_error_dir() -> str:
    return os.path.join(get_data_dir(), get_config_value(CONFIG_COLLECTION, CONFIG_COLLECTION_ERROR_DIR))

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
    
    def __init__(self):
        """Initialize the collector."""
        self.fqdn = socket.getfqdn()

    def update(self) -> None:
        """Called periodically while the collector is running. Execute any
        update routines required for the collector."""
        pass

    def cleanup(self) -> None:
        """Called after the collector has stopped."""
        pass
    
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
        
        # this is used to filter out submissions according to yara rules
        self.submission_filter = SubmissionFilter()
        
        # repository for database operations
        self.workload_repository = WorkloadRepository()
        self.workload_type_id = self.workload_repository.get_workload_type_id(self.config.workload_type)
        
        # file manager for file system operations
        self.file_manager = SubmissionFileManager(self.incoming_dir, self.persistence_dir)
        
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
        
        # load tuning rules
        self.submission_filter.load_tuning_rules()
        
        # initialize the submission scheduler
        self.submission_scheduler = SubmissionScheduler(
            self.workload_repository,
            self.file_manager,
            self.workload_type_id
        )

        # the execution mode for this collector service
        # defaults to normal operations (continuous)
        self.execution_mode: CollectorExecutionMode = CollectorExecutionMode.CONTINUOUS

    def start(self, single_threaded: bool = False, execution_mode: CollectorExecutionMode = CollectorExecutionMode.CONTINUOUS):
        self.load_groups()

        if not self.remote_node_groups:
            raise RuntimeError("no RemoteNodeGroup objects have been added to {}".format(self))

        if single_threaded:
            self.start_single_threaded(execution_mode)
        else:
            self.start_multi_threaded(execution_mode)

    def start_single_threaded(self, execution_mode: CollectorExecutionMode=CollectorExecutionMode.SINGLE_SHOT, execute_nodes: bool=True):
        assert execution_mode in [CollectorExecutionMode.SINGLE_SHOT, CollectorExecutionMode.SINGLE_SUBMISSION], "invalid execution mode for single threaded collector"
        
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
                logging.exception(f"unable to execute workload cleanup: {e}")
            
            if self.sleep(self.config.collection_frequency):
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
                submission_count = self.execute_collection_loop()

                if self.execution_mode == CollectorExecutionMode.SINGLE_SHOT:
                    self.shutdown_event.set()
                    break
                elif self.execution_mode == CollectorExecutionMode.SINGLE_SUBMISSION:
                    if submission_count > 0:
                        self.shutdown_event.set()
                        break

                # if we didn't process any submissions, wait before trying again
                if submission_count == 0:
                    self.sleep(self.config.collection_frequency)

            except Exception as e:
                logging.error(f"unexpected exception thrown during loop for {self}: {e}")
                report_exception()
                if self.sleep(1):
                    break
            finally:
                # this is a primary loop, so we need to release any database connections
                get_db().remove()
    
    def execute_collection_loop(self) -> int:
        submissions_processed = 0
        
        try:
            # collect submissions from the collector
            for submission in self.collector.collect():
                submissions_processed += 1
                
                # does this submission match any tuning rules we have?
                tuning_matches = self.submission_filter.get_tuning_matches(submission)
                if tuning_matches:
                    self.submission_filter.log_tuning_matches(submission, tuning_matches)
                    continue

                if submission.key:
                    if self.duplicate_filter.is_duplicate(submission.key):
                        logging.info(f"skipping duplicate submission {submission.key}")
                        continue

                    logging.debug(f"marking submission {submission.key} as processed")
                    self.duplicate_filter.mark_as_processed(submission.key)
                
                if self.submission_scheduler:
                    self.submission_scheduler.schedule_submission(submission, self.remote_node_groups)
                
                if self.is_shutdown():
                    break
                    
        except Exception as e:
            logging.error(f"error during collection: {e}")
            report_exception()
        
        # clear expired persistent data periodically
        self.clear_expired_persistent_data()
        return submissions_processed

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
                logging.exception(f"error during update: {e}")
                report_exception()

            if self.execution_mode in [CollectorExecutionMode.SINGLE_SHOT, CollectorExecutionMode.SINGLE_SUBMISSION]:
                break

            if self.sleep(self.config.collection_frequency):
                break
        
        logging.info("exited update loop")

    # utility routines
    # ------------------------------------------------------------------------
    
    def clear_expired_persistent_data(self):
        if self.duplicate_filter:
            self.duplicate_filter.clear_expired_data()

    def sleep(self, time: float) -> bool:
        """Waits for the specified time or until the shutdown event is set.
        Returns True if the shutdown event is set."""
        return self.shutdown_event.wait(time)

    def is_shutdown(self) -> bool:
        """Returns True if the collector is shutting down."""
        return self.shutdown_event.is_set()