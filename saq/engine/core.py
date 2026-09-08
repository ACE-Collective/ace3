import logging
import os
import signal
from multiprocessing import Process
from typing import Optional, Type, Union

from pydantic import BaseModel, Field


from saq.constants import NODE_STATUS_RUNNING, NODE_STATUS_STOPPED
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.worker_manager import WorkerManager
from saq.engine.node_manager.node_manager_factory import create_node_manager
from saq.engine.worker import Worker
from saq.environment import ACE_MP_CONTEXT, get_global_runtime_settings
from saq.error import report_exception
from saq.error.reporting import log_loop_exception
from saq.engine.configuration_manager import ConfigurationManager
from saq.service import ACEServiceInterface
from saq.shutdown import get_shutdown_coordinator
from saq.engine.enums import EngineState, EngineExecutionMode
from saq.configuration.schema import ServiceConfig

class EngineServiceMetricsLoggingConfig(BaseModel):
    enabled: bool = Field(..., description="set this to false to disable metrics logging")
    fluent_bit_hostname: str = Field(..., description="the hostname of the fluent-bit server")
    fluent_bit_port: int = Field(..., description="the port of the fluent-bit server")
    fluent_bit_tag: str = Field(..., description="the tag to use for fluent-bit logging")

class EngineServiceConfig(ServiceConfig):
    # analysis pool settings
    # if NO analysis pools are specified then a single pool with no equal priority will be created with a size equal to the number of CPU cores
    analysis_pools: dict[str, Union[str, int]] = Field(..., description="analysis pool settings")
    # in a multi-node configuration nodes are free to pull work from other nodes (target_nodes)
    # this setting is OPTIONAL and controls which nodes this node will pull work from
    # you can specify the special value of LOCAL to only pull work from the local node
    target_nodes: list[str] = Field(default_factory=list, description="optional list of nodes this node will pull work from")
    # how often to discard the worker processes and create new ones (in seconds) (disabled until restart issue resolved)
    auto_refresh_frequency: int = Field(..., description="how often to discard the worker processes and create new ones (in seconds)")
    # the default analysis mode if none is specified, or an unknown analysis mode is specified
    default_analysis_mode: str = Field(..., description="the default analysis mode if none is specified, or an unknown analysis mode is specified")
    # local/excluded analysis modes
    local_analysis_modes: list[str] = Field(..., description="local/excluded analysis modes")
    excluded_analysis_modes: list[str] = Field(..., description="local/excluded analysis modes")
    # the nodes database table keeps track of all the ace nodes that are currently available
    # this settings specifies how often (in seconds) we update the table with our current information
    node_status_update_frequency: int = Field(..., description="how often (in seconds) we update the table with our current information")
    # if this is set to yes then any analysis that fails is copied to a directory for review later (can take a lot of disk space)
    copy_analysis_on_error: bool = Field(..., description="if this is set to yes then any analysis that fails is copied to a directory for review later")
    # if this is set to yes then any time an analysis module fails when analyzing a file, the engine will copy that file, along with details, to a directory for review
    copy_file_on_error: bool = Field(..., description="if this is set to yes then any time an analysis module fails when analyzing a file, the engine will copy that file, along with details, to a directory for review")
    # make copies of files analyzed by analysis modules that ended up timing out and getting killed by the worker manager (can take a lot of disk space)
    copy_terminated_analysis_causes: bool = Field(..., description="make copies of files analyzed by analysis modules that ended up timing out and getting killed by the worker manager")
    # in some cases you might want your work to be performed on a different hard drive; if set then new non-alert analysis will be performed in this directory (relative to SAQ_HOME)
    work_dir: Optional[str] = Field(default=None, description="in some cases you might want your work to be performed on a different hard drive; if set then new non-alert analysis will be performed in this directory (relative to SAQ_HOME)")
    # when an analyst dispositions an alert ace will stop analyzing it if the alert is in correlation mode
    # this specifies how often ace checks the database for the disposition value (in seconds)
    alert_disposition_check_frequency: int = Field(..., description="how often ace checks the database for the disposition value (in seconds)")
    # a comma separated list of analysis modes that will NOT become alerts if detections are made (correlation, dispositioned, event)
    non_detectable_modes: list[str] = Field(..., description="a comma separated list of analysis modes that will NOT become alerts if detections are made")
    # yes/no to stop any running analysis on an alert if it is dispositioned before the analysis completes
    stop_analysis_on_any_alert_disposition: bool = Field(..., description="yes/no to stop any running analysis on an alert if it is dispositioned before the analysis completes")
    # A comma separated list of alert dispositions to trigger stopping any running analysis in the alert.
    stop_analysis_on_dispositions: list[str] = Field(..., description="A comma separated list of alert dispositions to trigger stopping any running analysis in the alert")
    # A comma separated list of analysis modes that should ignore the cumulative analysis timeout.
    analysis_modes_ignore_cumulative_timeout: list[str] = Field(..., description="A comma separated list of analysis modes that should ignore the cumulative analysis timeout")
    # If this is set to yes then whenever an analysis times out completely it gets logged at the WARNING level instead of ERROR (useful in unstable environments)
    log_analysis_timeout_as_warning: bool = Field(..., description="If this is set to yes then whenever an analysis times out completely it gets logged at the WARNING level instead of ERROR")
    # By default alerting is enabled. If this is set to no then the engine will not check to see if an analysis should become an alert.
    alerting_enabled: bool = Field(..., description="By default alerting is enabled. If this is set to no then the engine will not check to see if an analysis should become an alert")
    pool_size_limit: Optional[int] = Field(default=None, description="The maximum number of workers that can be created for any analysis mode")
    # metrics logging configuration
    metrics_logging: EngineServiceMetricsLoggingConfig = Field(..., description="metrics logging configuration")

class Engine():
    """Analysis Correlation Engine with Unified Controller"""

    def __init__(
        self,
        *args,
        config: Optional[EngineConfiguration] = None,
        execution_mode: EngineExecutionMode = EngineExecutionMode.NORMAL,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.state = EngineState.INITIALIZING
        self.execution_mode = execution_mode

        # configuration options
        # ------------------------------------------------------------

        self.config = config or EngineConfiguration(**kwargs)

        # this is used to control the main loop
        self.loop_control_event = ACE_MP_CONTEXT.Event()

        # set once the engine has started
        self.started_event = ACE_MP_CONTEXT.Event()
        
        # SIGHUP is the only signal the engine handles itself (worker reload). shutdown
        # signals belong to the process-wide ShutdownCoordinator.
        self.sighup_received = False

        # initialize configuration manager
        self.configuration_manager = ConfigurationManager(self.config)

        # node manager for cluster and node management
        self.node_manager = create_node_manager(self.configuration_manager)

        # worker manager for managing worker processes
        self.worker_manager = WorkerManager(self.configuration_manager, self.node_manager)

        # make sure these exist
        for directory in [self.config.stats_dir, self.config.work_dir]:
            if directory:
                os.makedirs(directory, exist_ok=True)

        # initialize node configuration and database setup
        self.node_manager.initialize_node()

        # for single threaded execution
        self.single_threaded_worker: Optional[Worker] = None

    def __str__(self):
        return "Engine ({})".format(get_global_runtime_settings().saq_node)

    def _set_state(self, state: EngineState):
        """Sets the state of the engine."""
        if self.state != state:
            self.state = state
            logging.info("engine state changed to {}".format(state))

    def start(self, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Starts the engine. This function does not return until the engine is stopped."""
        logging.info("starting engine controller")
        
        self.main_controller_loop(execution_mode=execution_mode)

    # ------------------------------------------------------------
    # Debug methods
    # ------------------------------------------------------------

    def start_single_shot(self):
        """Starts the engine in single-shot mode. Executes a single work item and then shuts down."""
        self.start(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    def start_nonblocking(self) -> Process:
        """Starts the engine on another process. Returns the created Process object."""
        process = ACE_MP_CONTEXT.Process(target=self.start)
        process.start()
        return process

    def wait_for_start(self, timeout: Optional[float]=None) -> bool:
        """Waits for the engine to start."""
        return self.started_event.wait(timeout)

    def start_single_threaded(self, analysis_priority_mode: Optional[str]=None, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Starts the engine in single-threaded mode. In this mode a single
        worker is used to execute all work items directly."""
        logging.info("starting engine in single-threaded mode")

        # set single threaded mode
        self.config.single_threaded_mode = True
        
        # run single threaded execution
        self.single_threaded_execution_loop(analysis_priority_mode=analysis_priority_mode, execution_mode=execution_mode)

    # ------------------------------------------------------------
    # control loops
    # ------------------------------------------------------------

    def main_controller_loop(self, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Main controller loop that manages workers and handles signals."""
        logging.info("started engine controller on process {} in mode {}".format(os.getpid(), execution_mode))
        
        # initialize signal handlers
        self.initialize_signal_handlers()
        
        # initialize and start the worker manager
        self.worker_manager.initialize_workers()
        self.worker_manager.start_workers(execution_mode=execution_mode)
        
        logging.info("entering main controller loop")
        self._set_state(EngineState.RUNNING)
        self.node_manager.set_status(NODE_STATUS_RUNNING)
        self.started_event.set()

        coordinator = get_shutdown_coordinator()

        while True:
            try:
                if execution_mode in [EngineExecutionMode.SINGLE_SHOT, EngineExecutionMode.UNTIL_COMPLETE]:
                    logging.info(f"execution mode {execution_mode} enabled - shutting down after processing")
                    self._controlled_stop()
                    break

                # SIGTERM and SIGINT mean the same thing and take the same path. docker
                # sends SIGTERM and an operator at a terminal sends SIGINT; both mean
                # "stop now", and in-flight analysis is abandoned and requeued rather
                # than finished, so another node can pick it up immediately.

                if coordinator.is_shutting_down:
                    logging.info("shutdown requested (%s)", coordinator.reason)
                    self._immediate_stop()
                    break

                # update node status and execute primary node routines if needed
                self.node_manager.update_node_status_and_execute_primary_routines()

                # check workers and restart if needed
                self.worker_manager.check_workers()

                if self.sighup_received:
                    # we re-load the config when we receive SIGHUP
                    #logging.info("reloading engine configuration")
                    self.sighup_received = False

                    # tell the manager to reload the workers
                    self.worker_manager.restart_workers()
                    # and then reload the configuration
                    # TODO: though needs to be put into allowing the configuration to be reloaded
                    #from saq.configuration.parser import load_configuration
                    #load_configuration()

                # if this event is set then we need to exit now
                if self.state in [EngineState.IMMEDIATE_SHUTDOWN, EngineState.CONTROLLED_SHUTDOWN]:
                    break

                # execute loop every second
                self.loop_control_event.wait(1.0)

            except Exception as e:
                log_loop_exception(e, "unexpected exception thrown in main controller loop")
                self.loop_control_event.wait(1.0)

        logging.info("ended main controller loop")
        self._set_state(EngineState.STOPPED)

        # release the locks this node still holds so the work they were blocking is
        # claimable by another node right away rather than after lock_timeout_seconds.
        # the workers have exited by now, so nothing is going to re-take them.
        self.node_manager.clear_node_locks("this node shutting down")

        # tell the cluster we are gone. doing this last means peers stop routing work
        # here only once there is genuinely nothing left running to receive it.
        self.node_manager.set_status(NODE_STATUS_STOPPED)

    def initialize_single_threaded_worker(self, analysis_priority_mode: Optional[str]=None, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL) -> Worker:
        """Initializes a single-threaded worker."""
        self.single_threaded_worker = Worker("worker-1", self.configuration_manager, self.node_manager, analysis_mode_priority=analysis_priority_mode)
        return self.single_threaded_worker

    def single_threaded_execution_loop(self, analysis_priority_mode: Optional[str]=None, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Single-threaded execution loop for debugging."""
        logging.info("starting single-threaded execution loop in execution mode {} with priority override {}".format(execution_mode, analysis_priority_mode))

        if not self.single_threaded_worker:
            self.initialize_single_threaded_worker(analysis_priority_mode, execution_mode)

        assert self.single_threaded_worker is not None
        
        # main execution loop
        while True:
            try:
                # execute a single work item
                self.single_threaded_worker.single_threaded_start(execution_mode=execution_mode)
                    
            except KeyboardInterrupt:
                logging.info("received keyboard interrupt")
                break
            except Exception as e:
                logging.error(f"error in single-threaded execution: {e}")
                report_exception()
                break

            break
        
        logging.info("single-threaded execution loop ended")

    def initialize_signal_handlers(self):
        """Initialize the signal handlers the engine owns."""
        def handle_sighup(signum, frame):
            self.sighup_received = True

        signal.signal(signal.SIGHUP, handle_sighup)

        # if the engine is running outside the service runner (tests, `ace correlate`)
        # nobody has installed the shutdown handlers yet, so do it here
        get_shutdown_coordinator().install_signal_handlers()

    # ------------------------------------------------------------
    # control methods
    # ------------------------------------------------------------

    def _immediate_stop(self):
        """Stop the engine now, abandoning in-flight analysis.

        Abandoning is not the same as being killed. Each worker cancels the analysis it
        is running so that it unwinds through its own finally blocks -- releasing its
        lock and clearing its tracking record -- which leaves the workload row intact and
        immediately claimable by another node. A SIGKILL'd worker leaves the same row
        behind but with a lock nobody releases for lock_timeout_seconds (5 minutes by
        default), which is why the work appeared to stall after a restart.
        """
        logging.info("stopping engine NOW")
        self._set_state(EngineState.IMMEDIATE_SHUTDOWN)

        # wake the controller loop out of its 1 second tick
        self.loop_control_event.set()

        self.worker_manager.immediate_shutdown()

    def _controlled_stop(self):
        """Shutdown the engine in a controlled manner allowing existing jobs to complete."""
        logging.info("stopping engine")
        self._set_state(EngineState.CONTROLLED_SHUTDOWN)

        # wake the controller loop out of its 1 second tick
        self.loop_control_event.set()

        self.worker_manager.controlled_shutdown()

class EngineService(ACEServiceInterface):
    def __init__(self):
        self.engine = Engine()

    def start(self):
        self.engine.start()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.engine.wait_for_start(timeout)
    
    def start_single_threaded(self):
        self.engine.start_single_threaded()
    
    def wait(self):
        # Engine.start() blocks in the controller loop until the engine has stopped, so
        # by the time anything calls wait() there is nothing left to wait for.
        pass

    def stop(self):
        # abandon in-flight analysis and requeue it rather than draining, so the node
        # exits promptly and another node picks the work up. draining a node before
        # stopping it is a separate, operator-driven action (`ace node drain`).
        if self.engine.state in (EngineState.IMMEDIATE_SHUTDOWN, EngineState.CONTROLLED_SHUTDOWN, EngineState.STOPPED):
            logging.debug("engine already stopping (state %s)", self.engine.state)
            return

        self.engine._immediate_stop()

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return EngineServiceConfig