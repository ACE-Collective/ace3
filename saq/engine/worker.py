from datetime import datetime, timedelta
import logging
from multiprocessing import Event, Process
import os
import shutil
import signal
import time
from typing import Optional, Union
import uuid

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config_value
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED, CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR, F_FILE, LockManagerType, WorkloadManagerType
from saq.database.pool import get_db
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.delayed_analysis_adapter import DelayedAnalysisAdapter
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.engine.lock_manager.adapter import LockManagerAdapter
from saq.engine.lock_manager.distributed import DistributedLockManager
from saq.engine.lock_manager.local import LocalLockManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.tracking import TrackingMessageManager
from saq.engine.workload_manager.adapter import WorkloadManagerAdapter
from saq.engine.workload_manager.database import DatabaseWorkloadManager
from saq.engine.workload_manager.interface import WorkloadManagerInterface
from saq.engine.workload_manager.memory import MemoryWorkloadManager
from saq.environment import get_data_dir
from saq.error.reporting import report_exception
from saq.modules.interfaces import AnalysisModuleInterface


from saq.observables.file import FileObservable
from saq.util.process import kill_process_tree
from saq.util.time import local_time
from saq.util.uuid import storage_dir_from_uuid, workload_storage_dir

class Worker:
    """Responsible for maintaining an executing analysis process."""

    def __init__(
        self, 
        name: str,
        configuration_manager: ConfigurationManager,
        node_manager: NodeManagerInterface,
        idle_timeout_max: Optional[int] = None,
        analysis_mode_priority: Optional[str] = None
    ):
        self.name = name
        self.process = None
        self.configuration_manager: ConfigurationManager = configuration_manager
        self.node_manager: NodeManagerInterface = node_manager
        self.config: EngineConfiguration = self.configuration_manager.config
        self.analysis_mode_priority: Optional[str] = analysis_mode_priority if analysis_mode_priority is not None else self.config.analysis_mode_priority

        # controls when the worker exits
        self._controlled_shutdown_event = Event()
        self._immediate_shutdown_event = Event()

        # set this Event once you're started up and are running
        self._worker_startup_event = Event()

        # the time at which we will automatically refresh the worker
        self._next_auto_refresh_time = None  # datetime

        # used to track the current work target and analysis module
        self.tracking_message_manager = TrackingMessageManager(name)

        # maximum amount of time to wait until looking for new work again
        self.idle_timeout_max = idle_timeout_max or 5

        self.lock_manager = self._create_lock_manager(self.config.lock_manager_type)
        self.workload_manager = self._create_workload_manager(self.config.workload_manager_type)
        self.analysis_orchestrator = self._create_analysis_orchestrator()

    def __str__(self):
        return f"worker {self.name}"

    #
    # DELAYED ANALYSIS
    # ------------------------------------------------------------------------

    def get_delayed_analysis_timeout(self, start_time: datetime, timeout_hours: Optional[int] = None, timeout_minutes: Optional[int] = None, timeout_seconds: Optional[int] = None) -> datetime:
        """Returns the timeout for the delayed analysis."""
        return start_time + timedelta(
            hours=0 if timeout_hours is None else timeout_hours,
            minutes=0 if timeout_minutes is None else timeout_minutes,
            seconds=0 if timeout_seconds is None else timeout_seconds,
        )

    def is_delayed_analysis_timed_out(self, root: RootAnalysis, observable: Observable, analysis_module: AnalysisModuleInterface, timeout_hours: Optional[int] = None, timeout_minutes: Optional[int] = None, timeout_seconds: Optional[int] = None) -> bool:
        """Returns True if the delayed analysis for the given root has timed out."""

        # if there's no timeout set then we don't need to check
        if timeout_hours is None and timeout_minutes is None and timeout_seconds is None:
            return False
        
        # we track the starting time in the root
        start_time = root.initialize_delayed_analysis_start_time(observable, analysis_module)
        assert start_time.tzinfo is not None and start_time.tzinfo.utcoffset(start_time) == timedelta(0), "start_time timezone must be UTC"

        # calculate the timeout
        timeout = self.get_delayed_analysis_timeout(start_time, timeout_hours, timeout_minutes, timeout_seconds)
        if local_time() >= timeout:
            return True

        logging.debug(
            "delayed analysis for {} in {} has been waiting for {} seconds".format(
            observable,
            analysis_module,
            (local_time() - start_time).total_seconds(),
        ))

        return False

    def delay_analysis(
        self,
        root,
        observable,
        analysis,
        analysis_module,
        hours=None,
        minutes=None,
        seconds=None,
        timeout_hours=None,
        timeout_minutes=None,
        timeout_seconds=None,
    ):
        # assert hours or minutes or seconds
        assert isinstance(root, RootAnalysis)
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)
        assert isinstance(analysis_module, AnalysisModuleInterface)

        if analysis.delayed:
            logging.warning(
                "analysis for {} by {} seems to already be scheduled".format(
                    observable, analysis_module
                )
            )

        if self.is_delayed_analysis_timed_out(root, observable, analysis_module, timeout_hours, timeout_minutes, timeout_seconds):
            logging.warning(f"delayed analysis for {observable} in {analysis_module} has timed out")
            return False

        # add the request to the workload
        if self.workload_manager.add_delayed_analysis_request(
            root,
            observable,
            analysis_module,
            hours,
            minutes,
            seconds,
        ):
            analysis.delayed = True

        return True

    def _create_lock_manager(self, lock_manager_type: LockManagerType):
        lock_owner = f"worker-{self.name}"
        if lock_manager_type == LockManagerType.LOCAL:
            return LockManagerAdapter(lock_manager=LocalLockManager(lock_owner=lock_owner))
        elif lock_manager_type == LockManagerType.DISTRIBUTED:
            return LockManagerAdapter(lock_manager=DistributedLockManager(lock_owner=lock_owner))

    def _create_workload_manager(self, workload_manager_type: WorkloadManagerType) -> WorkloadManagerInterface:
        # if we don't specify a workload manager interface, use the database workload manager
        if workload_manager_type == WorkloadManagerType.DATABASE:
            return WorkloadManagerAdapter(DatabaseWorkloadManager(
                configuration_manager=self.configuration_manager,
                node_manager=self.node_manager,
                lock_manager=self.lock_manager,
                analysis_mode_priority=self.analysis_mode_priority
            ))
        elif workload_manager_type == WorkloadManagerType.MEMORY:
            return WorkloadManagerAdapter(MemoryWorkloadManager(
                configuration_manager=self.configuration_manager,
                node_manager=self.node_manager,
                lock_manager=self.lock_manager,
                analysis_mode_priority=self.analysis_mode_priority
            ))
        else: # pragma: no cover
            raise RuntimeError(f"unsupported workload manager type: {workload_manager_type}")

    def _create_analysis_executor(self):
        """Create an AnalysisExecutor instance with the current engine configuration."""
        return AnalysisExecutor(
            configuration_manager=self.configuration_manager,
            delayed_analysis_interface=DelayedAnalysisAdapter(self),
            tracking_message_manager=self.tracking_message_manager,
            single_threaded_mode=self.config.single_threaded_mode
        )

    def _create_analysis_orchestrator(self):
        """Create an AnalysisOrchestrator instance with the current engine configuration."""
        return AnalysisOrchestrator(
            configuration_manager=self.configuration_manager,
            analysis_executor=self._create_analysis_executor(),
            workload_manager=self.workload_manager,
            lock_manager=self.lock_manager
        )

    #
    # MANGER INTERFACE
    # ------------------------------------------------------------------------

    def is_in_shutdown_state(self) -> bool:
        """Returns True if the worker is in a shutdown state."""
        return self._immediate_shutdown_event.is_set() or self._controlled_shutdown_event.is_set()

    def start(self, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL) -> Process:
        """Non-blocking call to start the worker. Returns the Process object created for the worker."""
        self.process = Process(
            target=self.worker_loop,
            name="Worker [{}]".format(self.config.analysis_mode_priority if self.config.analysis_mode_priority else "any"),
            kwargs={"execution_mode": execution_mode}
        )
        self.process.start()
        return self.process

    def single_threaded_start(self, execution_mode: EngineExecutionMode):
        self.worker_loop(execution_mode)

    def wait_for_start(self):
        while not self._worker_startup_event.wait(30):
            logging.warning(f"worker for {self.config.analysis_mode_priority} not starting ({self.process.pid if self.process else 'unknown'})")

            try:
                if self.process:
                    kill_process_tree(self.process.pid, signal.SIGKILL)
            except Exception as e:
                logging.error(f"unable to kill process {self.process}: {e}")

            if self.is_in_shutdown_state():
                break

    def immediate_shutdown(self):
        """Stop the worker immediately."""
        logging.info(f"sending signal to shut down worker {self.name} immediately")
        self._immediate_shutdown_event.set()

    def controlled_shutdown(self):
        """Stop the worker when it has finished processing all work."""
        logging.info(f"sending signal to shut down worker {self.name} when complete")
        self._controlled_shutdown_event.set()

    def wait(self, timeout: float = 60):
        """Wait for the worker to finish processing all work."""
        if self.process is None:
            logging.warning("worker has no process to wait for")
            return

        logging.info("waiting for {}...".format(self.process))

        self.process.join(timeout)
        if self.process.is_alive():
            if self._immediate_shutdown_event.is_set():
                logging.warning("process {} not stopping".format(self.process))

            self.process.kill()
            self.process.join(0) # reap the zombie

    #
    # WORKER INTERFACE
    # ------------------------------------------------------------------------

    def worker_loop(self, execution_mode: EngineExecutionMode):
        
        logging.info(
            "started worker {} loop on process {} with priority {}".format(
                self.name, os.getpid(), self.config.analysis_mode_priority
            )
        )

        # load available analysis modules
        try:
            self.configuration_manager.load_modules()
        except Exception as e:
            logging.error("unable to load modules: {} (worker exiting)".format(e))
            report_exception()
            return False

        # let the main process know we started
        self._worker_startup_event.set()

        # if auto_refresh_frequency is > 0 then we record when we want to call it quits and start a new process
        if self.config.auto_refresh_frequency:
            self._next_auto_refresh_time = datetime.now() + timedelta(
                seconds=self.config.auto_refresh_frequency
            )
            logging.debug(
                f"next auto refresh time for {os.getpid()} set to {self._next_auto_refresh_time}"
            )

        idle_time = 0

        if execution_mode == EngineExecutionMode.UNTIL_COMPLETE:
            logging.info("single shot mode - shutting down after completing work")
            self._controlled_shutdown_event.set()

        # check for any failed analysis that may have occurred before we started
        self._handle_failed_analysis()

        while True:
            # is this worker shutting down?
            if self._immediate_shutdown_event.is_set():
                break
            
            # is it time to die?
            if self._next_auto_refresh_time:
                if datetime.now() > self._next_auto_refresh_time:
                    logging.info(
                        "auto refresh frequency {} triggered reload of worker modules".format(
                            self.config.auto_refresh_frequency
                        )
                    )
                    break

            try:
                # if the control event is set then it means we're looking to exit when everything is done
                if self._controlled_shutdown_event.is_set():
                    if (
                        self.workload_manager.delayed_analysis_queue_is_empty
                        and self.workload_manager.workload_queue_is_empty
                    ):
                        logging.debug(
                            "both queues are empty - broke out of engine loop"
                        )
                        break  # break out of the main loop

                    logging.debug(
                        "queue sizes workload {} delayed {}".format(
                            self.workload_manager.workload_queue_size,
                            self.workload_manager.delayed_analysis_queue_size,
                        )
                    )

                # Worker is responsible for tracking the work target
                work_item = self.workload_manager.get_next_work_target()
                if work_item:
                    # Track the work target at the Worker level
                    self.tracking_message_manager.track_current_work_target(work_item)
                    
                    try:
                        # if execute returns True it means it discovered and processed a work_item
                        # in that case we assume there is more work to do and we check again immediately
                        if self.execute(work_item):
                            idle_time = 0
                            continue
                    finally:
                        # Clear tracking for the completed target
                        self.tracking_message_manager.clear_target_tracking()
                else:
                    # increment idle time when no work is found
                    idle_time = min(idle_time + 1, self.idle_timeout_max)

                    # otherwise we wait a second until we go again
                    # if we're in an immediate shutdown state then we don't wait at all here
                    if self._immediate_shutdown_event.wait(idle_time):
                        break

                if execution_mode == EngineExecutionMode.SINGLE_SHOT:
                    logging.info("single shot mode - shutting down after processing one work item")
                    break

            except Exception as e:
                logging.error("uncaught exception in worker_loop: {}".format(e))
                report_exception()
                time.sleep(1) # avoid spinning
            finally:
                # SQLAlchemy session management
                db_session = get_db()
                if db_session is not None:
                    db_session.remove()
                    db_session.close()

        logging.debug("worker {} exiting".format(os.getpid()))

    def execute(self, work_item: Union[RootAnalysis, DelayedAnalysisRequest]):
        """Execute a single work item using the AnalysisOrchestrator."""

        logging.debug("got work item {}".format(work_item))

        # Create execution context for this work item
        execution_context = EngineExecutionContext(work_item)

        # at this point the thing to work on is locked (using the locks database table)
        # start a secondary thread that just keeps the lock open
        if not self.config.single_threaded_mode:
            if not self.lock_manager.start_keepalive(work_item.uuid):
                logging.error("detected lock failure for work item {}".format(work_item))
                self.current_execution_context = None
                return

        try:
            work_dir = get_config_value(CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR)

            if (
                # if the work target is a root analysis object,
                isinstance(work_item, RootAnalysis)
                # and it is not an alert,
                and work_item.analysis_mode not in [ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED]
                # and this system uses a work directory for analysis,
                and work_dir
                # and the storage directory is currently set to the main data directory
                and work_item.storage_dir == storage_dir_from_uuid(work_item.uuid)
            ):
                logging.info(f"switching to work directory for {work_item}")
                # then we move the storage directory to the work directory
                # first we need to load it
                work_item.load()
                # then we can move it
                self.analysis_orchestrator._relocate_storage_directory(workload_storage_dir(work_item.uuid), execution_context)
                # and re-track to that new target location
                self.tracking_message_manager.track_current_work_target(work_item)

            # Use the AnalysisOrchestrator to handle the complete analysis lifecycle
            success = self.analysis_orchestrator.orchestrate_analysis(execution_context)
            
            if not success:
                logging.warning(f"analysis orchestration failed for {work_item}")

        except Exception as e:
            logging.error("error orchestrating analysis for {}: {}".format(work_item, e))
            report_exception(execution_context)

        finally:
            # Clean up: stop keepalive and clear work target
            if not self.config.single_threaded_mode:
                self.lock_manager.stop_keepalive()
            self.workload_manager.clear_work_target(work_item)
            # Clear the execution context
            self.current_execution_context = None

    def analysis_has_timed_out(self) -> bool:
        """Returns True if the current analysis has timed out (is stuck)."""

        #
        # NOTE this is called by the manager
        #

        # is it taking too long to analyze something?
        last_analysis_module = self.tracking_message_manager.get_current_analysis_module()
        last_work_target = self.tracking_message_manager.get_current_work_target()
        if last_analysis_module is None:
            return False

        threshold = last_analysis_module.start_time + timedelta(seconds=last_analysis_module.maximum_analysis_time)
        if datetime.now() > threshold:
            logging.error(
                f"analysis module {last_analysis_module} "
                f"timed out analyzing {last_work_target if last_work_target else 'unknown'} "
                f"on pid {self.process.pid if self.process else 'unknown'}"
            )
            return True

        return False

    def _handle_failed_analysis(self):
        # was the process executing an analysis module?
        last_work_target = self.tracking_message_manager.get_current_work_target()
        last_analysis_module = self.tracking_message_manager.get_current_analysis_module()

        if not last_work_target or not last_analysis_module:
            return

        logging.warning(
            f"detected failed analysis module {last_analysis_module} while analyzing {last_work_target}"
        )

        try:
            root = RootAnalysis(storage_dir=last_work_target)
            root.load()

            if self.config.copy_terminated_analysis_causes:
                try:
                    failed_analysis_dir = os.path.join(
                        get_data_dir(),
                        "review",
                        "failed_analysis",
                        datetime.now().strftime("%Y"),
                        datetime.now().strftime("%m"),
                        datetime.now().strftime("%d"),
                        root.uuid,
                    )

                    os.makedirs(failed_analysis_dir, exist_ok=True)

                    # if the observable was a file then copy the file and these details so they can be reviewed
                    if last_analysis_module.observable_type == F_FILE:
                        # find the file observable with this value
                        file_observable = root.find_observable(
                            lambda _: _.type == F_FILE
                            and _.value == last_analysis_module.observable_value
                        )
                        if isinstance(file_observable, FileObservable):
                            logging.info(
                                "copying file that failed analysis from %s to %s",
                                file_observable.full_path,
                                failed_analysis_dir,
                            )
                            shutil.copy(
                                file_observable.full_path, failed_analysis_dir
                            )

                    target_uuid = last_analysis_module.observable_id or str(
                        uuid.uuid4()
                    )

                    with open(
                        os.path.join(failed_analysis_dir, f"details-{target_uuid}"),
                        "w",
                    ) as fp:
                        fp.write(
                            f"""root = {root.storage_dir}
work_target = {last_work_target}
analysis_module = {last_analysis_module}
"""
                        )
                except Exception as e:
                    logging.error(
                        f"unable to copy file observable to review directory: {e}"
                    )

            # mark the analysis as failed
            root.set_analysis_failed(
                last_analysis_module.module_path,
                last_analysis_module.observable_type,
                last_analysis_module.observable_value,
                error_message="process died unexpectedly",
            )

            root.save()

            # and then clear the lock on this so it can get picked up right away
            self.lock_manager.force_release_lock(root.uuid)

        except Exception as e:
            logging.error(f"unable to mark analysis as failed: {e}")
            report_exception()

        finally:
            self.tracking_message_manager.clear_target_tracking()
            self.tracking_message_manager.clear_module_tracking()