from datetime import datetime, timedelta
import logging
from operator import attrgetter
import os
import shutil
import threading
from typing import Optional, Union
from enum import Enum

import iptools
from saq.analysis.analysis import Analysis
from saq.analysis.errors import ExcessiveFileDataSizeError
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.configuration.config import (
    get_config,
    get_engine_config,
)
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    DIRECTIVE_EXCLUDE_ALL,
    DISPOSITION_OPEN,
    EVENT_ANALYSIS_ADDED,
    EVENT_ANALYSIS_MARKED_COMPLETED,
    EVENT_DETAILS_UPDATED,
    EVENT_DIRECTIVE_ADDED,
    EVENT_OBSERVABLE_ADDED,
    EVENT_RELATIONSHIP_ADDED,
    EVENT_TAG_ADDED,
    F_FILE,
    F_IPV4,
    STATE_POST_ANALYSIS_EXECUTED,
    STATE_PRE_ANALYSIS_EXECUTED,
    AnalysisExecutionResult,
)
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.delayed_analysis_interface import DelayedAnalysisInterface
from saq.engine.errors import (
    AnalysisFailedException,
    AnalysisTimeoutError,
    WaitForAnalysisException,
)
from saq.engine.tracking import TrackingMessageManager
from saq.engine.work_stack import WorkStack, WorkTarget
from saq.error import report_exception
from saq.filesystem.adapter import FileSystemAdapter
from saq.modules.context import AnalysisModuleContext
from saq.modules.interfaces import AnalysisModuleInterface
from saq.network_semaphore.client import NetworkSemaphore
from saq.util import local_time

from fluent import sender


class ObservableExclusionResult(Enum):
    EXCLUDED = "excluded"
    OK = "ok"


class AnalysisModuleMonitor:
    def __init__(
        self,
        root: RootAnalysis,
        analysis_module: AnalysisModuleInterface,
        work_item: WorkTarget,
        maximum_analysis_time: int,
    ):

        self.monitor_event = threading.Event()
        self.monitor_thread = threading.Thread(
            target=self.run,
            args=(
                root,
                self.monitor_event,
                analysis_module,
                work_item,
                maximum_analysis_time,
            ),
        )
        self.monitor_thread.daemon = True

    def start(self):
        self.monitor_thread.start()

    def stop(self):
        self.monitor_event.set()
        self.monitor_thread.join()

    def run(
        self,
        root: RootAnalysis,
        monitor_event: threading.Event,
        monitor_module: AnalysisModuleInterface,
        monitor_target: WorkTarget,
        maximum_analysis_time: int,
    ):
        logging.debug(f"starting monitor for {monitor_module} ({monitor_target})")
        monitor_start_time = datetime.now()
        timeout = min(maximum_analysis_time, monitor_module.maximum_analysis_time)
        monitor_event.wait(timeout=timeout)

        while not monitor_event.is_set():
            monitor_elapsed_time = (datetime.now() - monitor_start_time).total_seconds()
            if monitor_elapsed_time > maximum_analysis_time:
                logging.warning(
                    f"excessive time - analysis module {monitor_module} "
                    f"has been analyzing {monitor_target} "
                    f"for {monitor_elapsed_time} seconds"
                )

            # if the analysis module has specified a maximum analysis time then we kill the process
            # the worker manager will clean up the mess
            if monitor_elapsed_time > monitor_module.maximum_analysis_time:
                logging.error(
                    "analysis module {} has exceeded it's maximum analysis time of {} seconds".format(
                    monitor_module,
                    monitor_module.maximum_analysis_time,
                ))
                os._exit(1)

            # repeat warning every 5 seconds until we bail
            if monitor_event.wait(timeout=5):
                break


class AnalysisExecutionContext:
    """
    Context object that holds all runtime state for a single analysis execution.
    This separates the transient state from the configuration in AnalysisExecutor.
    """

    def __init__(self, analysis_target: Union[RootAnalysis, DelayedAnalysisRequest]):
        """Initialize the context with the analysis target."""
        assert isinstance(analysis_target, RootAnalysis) or isinstance(
            analysis_target, DelayedAnalysisRequest
        )

        # Set root and delayed analysis request based on target type
        if isinstance(analysis_target, RootAnalysis):
            self.root = analysis_target
            self.delayed_analysis_request = None
        elif isinstance(analysis_target, DelayedAnalysisRequest):
            self.root = analysis_target.root
            self.delayed_analysis_request = analysis_target

        # Runtime state variables
        self._cancel_analysis_flag = False
        self.total_analysis_time = {}
        self.work_stack = None
        self.work_stack_buffer = None
        self.first_pass = True
        self.last_disposition_check = datetime.now()
        self.final_analysis_mode = False
        self.last_analyze_time_warning = None

    @property
    def is_delayed_analysis(self) -> bool:
        """Returns True if the analysis target is a delayed analysis request."""
        return self.delayed_analysis_request is not None
    
    @property
    def cancel_analysis_flag(self):
        """Return whether analysis has been cancelled."""
        return self._cancel_analysis_flag

    def cancel_analysis(self):
        """Cancel the current analysis."""
        self._cancel_analysis_flag = True

    def record_execution_statistics(self, elapsed_time: float, stats_dir: str):
        """Records the execution statistics for the analysis.
        
        Args:
            elapsed_time: The total elapsed time for the analysis.
            stats_dir: The (base) directory to save the statistics to (typically g(G_MODULE_STATS_DIR)).
        """
        # save module execution time metrics
        try:
            engine_config = get_engine_config()
            if not engine_config.metrics_logging.enabled:
                return

            fluent_bit_sender = sender.FluentSender(
                engine_config.metrics_logging.fluent_bit_tag,
                host=engine_config.metrics_logging.fluent_bit_hostname,
                port=engine_config.metrics_logging.fluent_bit_port)

            current_time = local_time().strftime("%Y-%m-%d %H:%M:%S.%f")
            # how long did all the analysis take combined?
            _total = 0.0
            for key in self.total_analysis_time.keys():
                _total += self.total_analysis_time[key]

            for key in self.total_analysis_time.keys():
                percentage = 0.0
                if elapsed_time:
                    percentage = (self.total_analysis_time[key] / elapsed_time) * 100.0

                if not elapsed_time:
                    elapsed_time = 0

                fluent_bit_sender.emit(None, {
                    "timestamp": current_time,
                    "module": key,
                    "analysis_time_seconds": self.total_analysis_time[key],
                    "percentage": percentage,
                    "total_analysis_time_seconds": _total,
                    "total_time_seconds": elapsed_time,
                    "root_uuid": self.root.uuid,
                })

        except Exception as e:
            logging.error("unable to record statistics: {}".format(e))

class AnalysisExecutor:
    """Executes analysis modules on observables and manages the analysis workflow."""

    def __init__(
        self,
        configuration_manager: ConfigurationManager,
        delayed_analysis_interface: DelayedAnalysisInterface,
        tracking_message_manager: TrackingMessageManager,
        single_threaded_mode=False,
    ):
        """
        Initialize the AnalysisExecutor.

        Args:


            delayed_analysis_interface: Interface for delayed analysis
            tracking_message_manager: Manager for tracking analysis module execution
            single_threaded_mode: Whether running in single-threaded mode
        """
        self.configuration_manager = configuration_manager
        self.config = configuration_manager.config
        self.delayed_analysis_interface = delayed_analysis_interface
        self.tracking_message_manager = tracking_message_manager
        self.single_threaded_mode = single_threaded_mode

        # we keep track of total analysis time per module
        self.total_analysis_time = {}  # key = module.name, value = total_seconds

        # this is set to True to cancel the analysis going on in the process() function
        self._cancel_analysis_flag = False

    def execute(self, analysis_target: Union[RootAnalysis, DelayedAnalysisRequest]) -> AnalysisExecutionContext:
        """
        Execute analysis on the given target.

        Args:
            analysis_target: Either a RootAnalysis or DelayedAnalysisRequest

        Returns:
            AnalysisExecutionContext containing the runtime state from this execution
        """
        # Create a new execution context for this analysis
        context = AnalysisExecutionContext(analysis_target)

        # each module gets a brand new context for this analysis
        from saq.modules.state_repository import StateRepositoryFactory

        assert isinstance(context.root, RootAnalysis)

        state_repository = StateRepositoryFactory.create_root_analysis_repository(
            context.root
        )

        for analysis_module in self.configuration_manager.analysis_modules:
            analysis_module.set_context(
                AnalysisModuleContext(
                    delayed_analysis_interface=self.delayed_analysis_interface,
                    root=context.root,  # XXX needs adapter!
                    configuration_manager=self.configuration_manager,
                    filesystem=FileSystemAdapter(),
                    state_repository=state_repository,
                )
            )

        # track module pre and post analysis execution
        if STATE_PRE_ANALYSIS_EXECUTED not in context.root.state:
            context.root.state[STATE_PRE_ANALYSIS_EXECUTED] = {}

        if STATE_POST_ANALYSIS_EXECUTED not in context.root.state:
            context.root.state[STATE_POST_ANALYSIS_EXECUTED] = {}

        # when something goes wrong it helps to have the logs specific to this analysis
        assert context.root.storage_dir is not None
        logging_handler = logging.FileHandler(
            os.path.join(context.root.storage_dir, "saq.log")
        )
        logging_handler.setLevel(logging.getLogger().level)
        logging_handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logging.getLogger().addHandler(logging_handler)

        try:
            # we keep track of the total amount of time we've spent on this entire analysis (in seconds)
            if "total_analysis_time_seconds" not in context.root.state:
                context.root.state["total_analysis_time_seconds"] = 0

            # and when we actually started to analyze this
            if "analysis_start_time" not in context.root.state:
                context.root.state["analysis_start_time"] = local_time()

            # don't even start if we're already cancelled
            if not context.cancel_analysis_flag:
                self._execute_recursive_analysis(context)

            # do we NOT have any outstanding delayed analysis requests?
            if not context.root.delayed:
                self._execute_post_analysis(context)

            # logging.info("completed analysis {} successfully".format(analysis_target))

        except Exception as e:
            # this will happen from time to time so we just want to log this at warning level
            # if this configuration options is enabled
            # if isinstance(e, AnalysisTimeoutError):
            # logging.warning("analysis failed on {}: {}".format(context.root, e))
            # else:
            # logging.error("analysis failed on {}: {}".format(context.root, e))

            # XXX I think is is different than before
            # Make sure that execute_post_analysis still runs if the caught exception was an analysis timeout.
            if isinstance(e, AnalysisTimeoutError):
                try:
                    self._execute_post_analysis(context)
                except Exception as e:
                    logging.error(
                        f"unable to run _execute_post_analysis {context.root}: {e}"
                    )

            # Re-raise the exception for the caller to handle
            raise

        finally:
            # make sure we remove the logging handler that we added
            logging.getLogger().removeHandler(logging_handler)

        return context

    def cancel_analysis(self):
        """Cancel the current analysis."""
        # This method is kept for backwards compatibility but doesn't do anything
        # since cancellation is now handled per-context
        pass

    @property
    def cancel_analysis_flag(self):
        """Return whether analysis has been cancelled."""
        # This property is kept for backwards compatibility but always returns False
        # since cancellation is now handled per-context
        return False

    def get_analysis_modules_by_mode(
        self, analysis_mode
    ) -> list[AnalysisModuleInterface]:
        """Returns the list of analysis modules configured for the given mode."""
        if analysis_mode is None:
            result = self.configuration_manager.analysis_mode_mapping[self.config.default_analysis_mode]
        else:
            try:
                result = self.configuration_manager.analysis_mode_mapping[analysis_mode]
            except KeyError:
                logging.warning(
                    "invalid analysis mode {} - defaulting to {}".format(
                        analysis_mode, self.config.default_analysis_mode
                    )
                )
                logging.debug(f"analysis mode mapping: {self.configuration_manager.analysis_mode_mapping}")
                result = self.configuration_manager.analysis_mode_mapping[self.config.default_analysis_mode]

        return result

    def get_analysis_modules_for_work_item(
        self, work_item: WorkTarget, analysis_mode: str
    ) -> list[AnalysisModuleInterface]:
        """Returns the list of analysis modules that are applicable to the given work item."""

        # start with the list that is valid for the current analysis mode
        analysis_modules = self.get_analysis_modules_by_mode(analysis_mode)

        # an Observable can specify a limited set of analysis modules to run
        if (
            work_item.dependency is None
            and work_item.observable
            and work_item.observable.limited_analysis
        ):
            analysis_modules = []
            for target_module_name in work_item.observable.limited_analysis:
                if target_module_name not in self.configuration_manager.analysis_module_name_mapping:
                    logging.error(
                        "{} specified unknown limited analysis {}".format(
                            work_item, target_module_name
                        )
                    )
                else:
                    analysis_modules.append(
                        self.configuration_manager.analysis_module_name_mapping[target_module_name]
                    )

            logging.debug(
                "analysis for {} limited to {} modules ({})".format(
                    work_item.observable,
                    len(analysis_modules),
                    ",".join(work_item.observable.limited_analysis),
                )
            )

        # if the work_item includes a dependency then the analysis_module property will already be set
        elif work_item.analysis_module:
            logging.debug(
                "analysis for {} limited to {}".format(
                    work_item, work_item.analysis_module
                )
            )
            analysis_modules = [work_item.analysis_module]

        return analysis_modules

    def _get_analysis_module_by_generated_analysis(self, spec, instance=None):
        """Returns the analysis module that generates the given analysis type."""
        for analysis_module in self.configuration_manager.analysis_modules:
            if analysis_module.generated_analysis_type is None:
                continue

            assert isinstance(analysis_module, AnalysisModuleInterface)
            if isinstance(spec, str):
                if (
                    MODULE_PATH(
                        analysis_module.generated_analysis_type,
                        analysis_module.instance,
                    )
                    == spec
                ):
                    return analysis_module
            else:
                if analysis_module.generated_analysis_type == spec:
                    if instance is None or analysis_module.instance == instance:
                        return analysis_module

        logging.debug(
            f"cannot find analysis module that generates {spec} ({type(spec)}) (instance {instance})"
        )
        return None

    def _execute_post_analysis(self, context):
        """Execute post-analysis routines for all analysis modules."""
        logging.debug("executing post analysis routines for {}".format(context.root))

        state = context.root.state[STATE_POST_ANALYSIS_EXECUTED]
        for analysis_module in sorted(
            self.get_analysis_modules_by_mode(context.root.analysis_mode),
            key=attrgetter("priority"),
        ):
            if analysis_module.name not in state:
                state[analysis_module.name] = None

            # has this post analysis already executed and completed?
            if (
                state[analysis_module.name] == AnalysisExecutionResult.COMPLETED
            ):
                continue

            try:
                # give the modules an opportunity to do something after all analysis has completed
                logging.debug(
                    f"executing post analysis for module {analysis_module.name} on {context.root}"
                )
                state[analysis_module.name] = (
                    analysis_module.execute_post_analysis()
                )
                logging.debug(
                    f"post analysis for module {analysis_module.name} on {context.root} returned {state[analysis_module.name]}"
                )
            except Exception as e:
                logging.error(
                    "post analysis module {} failed: {}".format(analysis_module, e)
                )
                state[analysis_module.name] = True
                report_exception()

    def _execute_pre_analysis(self, context) -> bool:
        """Execute pre-analysis routines for all analysis modules.

        Returns:
            True if pre-analysis routines were executed successfully, False otherwise.
        """

        # first we execute any pre-analysis routines that are loaded for the current analysis mode
        # this may end up introducing more observables so we do this before we initialize our work stack
        if (
            context.delayed_analysis_request
        ):  # don't need to bother if we're working on a delayed analysis req
            return False

        target_analysis_mode = context.root.analysis_mode
        if (
            target_analysis_mode is None
            or target_analysis_mode not in self.configuration_manager.analysis_mode_mapping
        ):
            target_analysis_mode = self.config.default_analysis_mode

        state = context.root.state[STATE_PRE_ANALYSIS_EXECUTED]
        for analysis_module in sorted(
            self.configuration_manager.analysis_mode_mapping[target_analysis_mode], key=attrgetter("priority")
        ):
            if analysis_module.name not in state:
                try:
                    state[analysis_module.name] = bool(
                        analysis_module.execute_pre_analysis()
                    )
                except Exception:
                    logging.error(
                        "pre analysis module {} failed".format(analysis_module)
                    )
                    report_exception()
                    state[analysis_module.name] = False

            if context.cancel_analysis_flag:
                logging.debug(
                    "analysis for {} cancelled during pre-analysis".format(context.root)
                )
                return False

        return True

    def _initialize_work_stack(self, context):
        """Initialize the work stack for the analysis."""
        # our list of things to analyze (of type WorkTarget)
        context.work_stack = WorkStack()

        # temporary work stack buffer
        context.work_stack_buffer = []

        if context.delayed_analysis_request is not None:
            context.work_stack.append(
                WorkTarget(
                    observable=context.delayed_analysis_request.observable,
                    analysis_module=context.delayed_analysis_request.analysis_module,
                )
            )

            # we should have found 1 exactly
            if len(context.work_stack) != 1:
                raise RuntimeError(
                    "delayed analysis request {} references missing analysis module".format(
                        context.delayed_analysis_request
                    )
                )
        else:
            # otherwise we analyze everything
            for analysis in context.root.all_analysis:
                context.work_stack.append(analysis)

            for observable in context.root.all_observables:
                context.work_stack.append(observable)

        def _workflow_callback(target, event, *args, **kwargs):
            logging.debug(
                "WORKFLOW: detected change to {} with event {}".format(
                    target, event
                )
            )
            context.work_stack_buffer.append(target)

        def _register_analysis_event_listeners(analysis):
            analysis.add_event_listener(
                EVENT_OBSERVABLE_ADDED, _observable_added_callback
            )
            analysis.add_event_listener(EVENT_OBSERVABLE_ADDED, _workflow_callback)
            analysis.add_event_listener(EVENT_TAG_ADDED, _workflow_callback)
            analysis.add_event_listener(EVENT_DETAILS_UPDATED, _workflow_callback)
            analysis.add_event_listener(
                EVENT_ANALYSIS_MARKED_COMPLETED, _workflow_callback
            )

        def _register_observable_event_listeners(observable):
            observable.add_event_listener(
                EVENT_ANALYSIS_ADDED, _analysis_added_callback
            )
            observable.add_event_listener(EVENT_ANALYSIS_ADDED, _workflow_callback)
            observable.add_event_listener(EVENT_TAG_ADDED, _workflow_callback)
            observable.add_event_listener(EVENT_DIRECTIVE_ADDED, _workflow_callback)
            observable.add_event_listener(EVENT_RELATIONSHIP_ADDED, _workflow_callback)

        # when we add new Observable and Analysis objects we need to track those as well
        def _observable_added_callback(analysis, event, observable):
            _register_observable_event_listeners(observable)
            context.work_stack_buffer.append(observable)

        def _analysis_added_callback(observable, event, analysis):
            _register_analysis_event_listeners(analysis)
            context.work_stack_buffer.append(analysis)

        # initialize event listeners for the objects we already have
        _register_analysis_event_listeners(context.root)

        for analysis in context.root.all_analysis:
            _register_analysis_event_listeners(analysis)

        for observable in context.root.all_observables:
            _register_observable_event_listeners(observable)

    def _get_delayed_analysis_work_item(self, context) -> Optional[WorkTarget]:
        if context.delayed_analysis_request and context.first_pass:
            logging.debug(
                "processing delayed analysis request {}".format(
                    context.delayed_analysis_request
                )
            )
            work_item = (
                context.work_stack.popleft()
            )  # should be the only thing on the stack
            assert len(context.work_stack) == 0
            context.first_pass = False
            return work_item
        else:
            return None

    def _get_completed_dependency_work_item(self, context: AnalysisExecutionContext) -> Optional[WorkTarget]:
        assert isinstance(context.root, RootAnalysis)
        logging.debug(
            "%s active dependencies to process", len(context.root.active_dependencies)
        )
        # get the next dependency that is not waiting on an analysis module that is delayed
        for (
            dep
        ) in (
            context.root.active_dependencies
        ):  # these are returned in the correct order
            # do we need to execute the dependency anaylysis?
            if dep.ready:
                logging.debug(f"analyzing ready dependency {dep}")
                # has this already been completed?
                existing_analysis = dep.target_observable.get_analysis(
                    dep.target_analysis_type
                )
                if existing_analysis is False or existing_analysis is not None:
                    logging.debug(f"already analyzed obs {dep.target_observable} target {dep.target_analysis_type}")
                    dep.increment_status()
                else:
                    target_analysis_module = (
                        self._get_analysis_module_by_generated_analysis(
                            dep.target_analysis_type
                        )
                    )
                    if target_analysis_module is None:
                        raise RuntimeError(
                            "cannot find target analysis for {}".format(dep)
                        )

                    return WorkTarget(
                        observable=dep.target_observable,
                        analysis_module=target_analysis_module,
                        dependency=dep,
                    )

            logging.debug(f"detected completed active dependency {dep}")
            # re-analyze the original source observable that requested the dependency
            source_analysis_module = self._get_analysis_module_by_generated_analysis(
                dep.source_analysis_type
            )
            if source_analysis_module is None:
                raise RuntimeError(
                    "cannot find source analysis module for {}".format(dep)
                )

            return WorkTarget(
                observable=dep.source_observable,
                analysis_module=source_analysis_module,
                dependency=dep,
            )

    def _get_next_work_item(self, context) -> Optional[WorkTarget]:
        assert isinstance(context.work_stack, WorkStack)
        while len(context.work_stack) > 0:
            work_item = context.work_stack.popleft()

            # is this work item waiting on a dependency?
            if work_item.observable:
                # get the list of all non-resolved deps
                if [
                    d
                    for d in work_item.observable.dependencies
                    if not d.resolved and not d.failed
                ]:
                    logging.debug(
                        "{} has outstanding dependencies: {}".format(
                            work_item,
                            ",".join(
                                map(
                                    str,
                                    [
                                        d
                                        for d in work_item.observable.dependencies
                                        if not d.resolved
                                    ],
                                )
                            ),
                        )
                    )
                    # if this work item is waiting on a dependency then we skip it
                    # it's OK to do so because get_completed_dependency_work_item() will handle it
                    continue

            return work_item

        return None

    def _process_observable_exclusions(
        self, work_item: WorkTarget
    ) -> ObservableExclusionResult:
        if not work_item.observable:
            return ObservableExclusionResult.OK

        # has this thing been whitelisted?
        if work_item.observable.whitelisted:
            logging.info(f"{work_item.observable} was whitelisted -- not analyzing")
            if work_item.dependency:
                work_item.dependency.set_status_failed("whitelisted")
                work_item.dependency.increment_status()

            return ObservableExclusionResult.EXCLUDED

        # is this observable excluded?
        excluded = False
        if work_item.observable.type in self.config.observable_exclusions:
            exclusions = self.config.observable_exclusions[work_item.observable.type]
            if work_item.observable.type == F_IPV4:
                exclusions = [iptools.IpRange(x) for x in exclusions]
            for exclusion in exclusions:
                try:
                    if work_item.observable.value in exclusion:
                        excluded = True
                        break
                except Exception:
                    logging.debug(
                        "{} probably is not an IP address".format(
                            work_item.observable.value
                        )
                    )

        if excluded:
            logging.debug(
                "ignoring globally excluded observable {}".format(work_item.observable)
            )
            if work_item.dependency:
                work_item.dependency.set_status_failed("globally excluded observable")
                work_item.dependency.increment_status()

            return ObservableExclusionResult.EXCLUDED

        # check for the DIRECTIVE_EXCLUDE_ALL directive
        if work_item.observable.has_directive(DIRECTIVE_EXCLUDE_ALL):
            logging.debug(
                "ignoring observable {} with directive {}".format(
                    work_item.observable, DIRECTIVE_EXCLUDE_ALL
                )
            )
            if work_item.dependency:
                work_item.dependency.set_status_failed(
                    "directive {}".format(DIRECTIVE_EXCLUDE_ALL)
                )
                work_item.dependency.increment_status()

            return ObservableExclusionResult.EXCLUDED

        return ObservableExclusionResult.OK

    def _check_for_alert_disposition(
        self, context, analysis_mode: str, alert_uuid: str
    ):
        """Checks to see if an analyst dispositioned the alert while we've been looking at it.

        Returns:
            The (new) last time we checked for a disposition.
        """

        # has an analyst dispositioned this alert while we've been looking at it?
        if (
            datetime.now() - context.last_disposition_check
        ).total_seconds() > self.config.alert_disposition_check_frequency:
            if analysis_mode == ANALYSIS_MODE_CORRELATION:
                get_db().close()

                # Get the two different stop analysis setting values
                stop_analysis_on_any_alert_disposition = get_engine_config().stop_analysis_on_any_alert_disposition
                stop_analysis_on_dispositions = get_engine_config().stop_analysis_on_dispositions

                # Check to see if we need to stop analysis based on the settings
                disposition = (
                    get_db()
                    .query(Alert.disposition)
                    .filter(Alert.uuid == alert_uuid)
                    .scalar()
                )
                if (
                    disposition is not None
                    and stop_analysis_on_any_alert_disposition
                    and disposition != DISPOSITION_OPEN
                ):
                    logging.info(
                        f"stopping analysis on dispositioned alert {context.root}"
                    )
                    context.cancel_analysis()
                elif disposition in stop_analysis_on_dispositions:
                    logging.info(
                        f"stopping analysis on {disposition} dispositioned alert {context.root}"
                    )
                    context.cancel_analysis()
                elif disposition:
                    logging.debug(
                        f"alert {context.root} dispositioned as {disposition} but continuing analysis"
                    )

    def _get_maximum_cumulative_analysis_warning_time(self, analysis_mode: str) -> int:
        """Returns the maximum cumulative analysis warning time for the given analysis mode."""
        analysis_mode_config = get_config().get_analysis_mode_config(analysis_mode)
        if analysis_mode_config.maximum_cumulative_analysis_warning_time is not None:
            return analysis_mode_config.maximum_cumulative_analysis_warning_time
        else:
            return get_config().global_settings.maximum_cumulative_analysis_warning_time

    def _get_maximum_cumulative_analysis_fail_time(self, analysis_mode: str) -> int:
        """Returns the maximum cumulative analysis fail time for the given analysis mode."""
        analysis_mode_config = get_config().get_analysis_mode_config(analysis_mode)
        if analysis_mode_config.maximum_cumulative_analysis_fail_time is not None:
            return analysis_mode_config.maximum_cumulative_analysis_fail_time
        else:
            return get_config().global_settings.maximum_cumulative_analysis_fail_time

    def _get_maximum_analysis_time(self, analysis_mode: str) -> int:
        """Returns the maximum analysis time for the given analysis mode."""
        analysis_mode_config = get_config().get_analysis_mode_config(analysis_mode)
        if analysis_mode_config.maximum_analysis_time is not None:
            return analysis_mode_config.maximum_analysis_time
        else:
            return get_config().global_settings.maximum_analysis_time

    def _check_for_analysis_timeout(
        self,
        context,
        root: RootAnalysis,
        current_total_time: float,
        work_item: WorkTarget,
        work_stack: WorkStack,
    ):
        """Checks to see if the analysis has taken too long."""

        maximum_cumulative_analysis_warning_time = (
            self._get_maximum_cumulative_analysis_warning_time(root.analysis_mode)
        )
        maximum_cumulative_analysis_fail_time = (
            self._get_maximum_cumulative_analysis_fail_time(root.analysis_mode)
        )
        # maximum_analysis_time = self._get_maximum_analysis_time(root.analysis_mode)

        if current_total_time >= maximum_cumulative_analysis_warning_time:
            if (
                context.last_analyze_time_warning is None
                or (datetime.now() - context.last_analyze_time_warning).total_seconds()
                > 10
            ):
                context.last_analyze_time_warning = datetime.now()
                logging.warning(
                    f"ACE has been analyzing {root} for {current_total_time} seconds ({work_item}) ({len(work_stack)})"
                )

        ignore_modes = get_engine_config().analysis_modes_ignore_cumulative_timeout
        if current_total_time >= maximum_cumulative_analysis_fail_time:
            if root.analysis_mode in ignore_modes:
                logging.debug(f"ACE is ignoring cumulative timeout on {root}")
            else:
                raise AnalysisTimeoutError(f"ACE took too long to analyze {root}")

    def _check_module_acceptance(
        self, work_item: WorkTarget, analysis_module: AnalysisModuleInterface
    ) -> bool:
        """Checks to see if the analysis module accepts the work item."""
        if work_item.observable:
            # does this module accept this observable type?
            if not analysis_module.accepts(work_item.observable):
                if work_item.dependency:
                    work_item.dependency.set_status_failed("unaccepted for analysis")
                    work_item.dependency.increment_status()
                return False

            # are we NOT working on a delayed analysis request?
            # have we delayed analysis here?
            if analysis_module.generated_analysis_type is not None:
                target_analysis = work_item.observable.get_analysis(
                    analysis_module.generated_analysis_type,
                    instance=analysis_module.instance,
                )
                if target_analysis and target_analysis.delayed:
                    logging.debug(
                        "analysis for {} by {} has been delayed".format(
                            work_item, analysis_module
                        )
                    )
                    return False

        return True

    def _process_generated_analysis(
        self,
        analysis_result: AnalysisExecutionResult,
        root: RootAnalysis,
        work_item: WorkTarget,
        work_stack: WorkStack,
        work_stack_buffer: list[WorkTarget],
        analysis_module: AnalysisModuleInterface,
    ):
        """Processes the generated analysis for the given work item.

        - Handles the case where the analysis module did not generate analysis
        - Handles the case where the analysis module generated analysis and was not delayed.
        - Handles analysis module dependencies.
        """

        assert isinstance(work_item, WorkTarget)
        assert isinstance(work_item.observable, Observable)
        assert isinstance(work_stack, WorkStack)
        assert isinstance(work_stack_buffer, list)
        assert isinstance(analysis_module, AnalysisModuleInterface)

        # analysis that was added (if it was) to the observable is considered complete
        output_analysis = work_item.observable.get_analysis(
            analysis_module.generated_analysis_type, instance=analysis_module.instance
        )

        # did we not generate analysis?
        if (
            not output_analysis
            and analysis_result != AnalysisExecutionResult.INCOMPLETE
        ):
            logging.debug(
                f"analysis module {analysis_module} did not generate analysis for {work_item}"
            )
            work_item.observable.add_no_analysis(
                analysis_module.generated_analysis_type,
                instance=analysis_module.instance,
            )

        if output_analysis and analysis_result == AnalysisExecutionResult.COMPLETED:
            # if it hasn't been delayed
            if not output_analysis.delayed:
                logging.debug("analysis {} is completed".format(output_analysis))
                output_analysis.completed = True

        # did we just analyze a dependency?
        if work_item.dependency:
            # did we analyze the target analysis of a dependency?
            if work_item.dependency.ready:
                # if we did not generate any analysis then the dependency has failed
                if not output_analysis:
                    logging.debug(
                        "analysis module {} did not generate analysis to resolve dep {}".format(
                            analysis_module, work_item.dependency
                        )
                    )

                    work_item.dependency.set_status_failed("analysis not generated")
                    work_item.dependency.increment_status()
                    work_stack.appendleft(
                        WorkTarget(
                            observable=root.get_observable(
                                work_item.dependency.source_observable_id
                            ),
                            analysis_module=self._get_analysis_module_by_generated_analysis(
                                work_item.dependency.source_analysis_type
                            ),
                        )
                    )

                # if we do have output analysis and it's not delayed then we move on to analyze
                # the source target again
                elif not output_analysis.delayed:
                    work_item.dependency.increment_status()
                    logging.debug(
                        "dependency status updated {}".format(work_item.dependency)
                    )
                    work_stack.appendleft(
                        WorkTarget(
                            observable=root.get_observable(
                                work_item.dependency.source_observable_id
                            ),
                            analysis_module=self._get_analysis_module_by_generated_analysis(
                                work_item.dependency.source_analysis_type
                            ),
                        )
                    )

                # otherwise (if it's delayed) then we need to wait
                else:
                    logging.debug(
                        "{} {} waiting on delayed analysis".format(
                            analysis_module, work_item.observable
                        )
                    )

            # if we completed the source analysis of a dependency then we are done
            elif work_item.dependency.completed:
                work_item.dependency.increment_status()

    def _execute_module_analysis(
        self,
        context: AnalysisExecutionContext,
        root: RootAnalysis,
        work_item: WorkTarget,
        work_stack: WorkStack,
        work_stack_buffer: list[WorkTarget],
        analysis_module: AnalysisModuleInterface,
        start_time: datetime,
        total_analysis_time_seconds: float,
    ):

        assert isinstance(root, RootAnalysis)
        assert root.analysis_mode is not None

        module_start_time = None

        self._check_for_alert_disposition(context, root.analysis_mode, root.uuid)
        if context.cancel_analysis_flag:
            return

        # how long have we been analyzing?
        elapsed_time = (datetime.now() - start_time).total_seconds()
        current_total_time = elapsed_time + total_analysis_time_seconds

        # get the limits for the current analysis mode
        maximum_analysis_time = self._get_maximum_analysis_time(root.analysis_mode)

        self._check_for_analysis_timeout(
            context=context,
            root=root,
            current_total_time=current_total_time,
            work_item=work_item,
            work_stack=work_stack,
        )

        # if this module does not generate analysis then we skip this part
        if analysis_module.generated_analysis_type is None:
            return

        # does this module accept the work item?
        if not self._check_module_acceptance(work_item, analysis_module):
            return

        try:
            # have we already tried this and it didn't work?
            if root.is_analysis_failed(analysis_module, work_item.observable):
                logging.debug(
                    f"observable type {work_item.observable.type} value {work_item.observable.value}"
                    f" failed for analysis module {analysis_module} in {root} - skipping"
                )

                # let the exception handler deal with this so it can resolve depedencies
                raise AnalysisFailedException(
                    "analysis module failed in previous execution"
                )

            logging.debug(
                "analyzing {} with {} (final analysis={}) (delayed analysis={})".format(
                    work_item.observable, analysis_module, context.final_analysis_mode, context.is_delayed_analysis
                )
            )

            # track the analysis module that is currently analyzing this work item
            self.tracking_message_manager.track_current_analysis_module(analysis_module, work_item.observable)

            # start a monitor thread that will kill the process if the analysis module takes too long
            monitor = AnalysisModuleMonitor(
                root, analysis_module, work_item, maximum_analysis_time
            )
            monitor.start()

            # we default to completed if the analysis module does not return a valid result
            analysis_result: AnalysisExecutionResult = AnalysisExecutionResult.COMPLETED

            try:
                module_start_time = datetime.now()

                # if the analysis module has specified a semaphore name in the configuration
                # then we need to acquire the semaphore before analyzing
                if analysis_module.semaphore_name is not None:
                    with NetworkSemaphore(analysis_module.semaphore_name):
                        analysis_result = analysis_module.analyze(
                            work_item.observable, context.final_analysis_mode, context.is_delayed_analysis
                        )
                else:
                    analysis_result = analysis_module.analyze(
                        work_item.observable, context.final_analysis_mode, context.is_delayed_analysis
                    )

                logging.debug(
                    f"analysis module {analysis_module} returned {analysis_result} for {work_item}"
                )
                root.save()

            finally:
                # make sure we stop the monitor thread
                monitor.stop()

                # clear the tracking message for the analysis module
                self.tracking_message_manager.clear_module_tracking()

            # did the module cancel the analysis?
            if analysis_module.is_canceled_analysis():
                logging.info(
                    f"analysis module {analysis_module} cancelled analysis for {root} when analyzing {work_item}"
                )
                context.cancel_analysis()

            self._process_generated_analysis(
                analysis_result,
                root,
                work_item,
                work_stack,
                work_stack_buffer,
                analysis_module,
            )

        except WaitForAnalysisException as wait_exception:
            # first off, if we completed the source analysis of a dependency then we are done with that
            if work_item.dependency and work_item.dependency.completed:
                work_item.dependency.increment_status()

            # this analysis depends on the analysis of this other thing first
            logging.debug(
                "analysis of {} by {} depends on obs {} analyzed by {}".format(
                    work_item,
                    analysis_module,
                    wait_exception.observable,
                    wait_exception.analysis,
                )
            )

            # make sure the requested analysis module is available
            if not self._get_analysis_module_by_generated_analysis(
                wait_exception.analysis, instance=wait_exception.instance
            ):
                raise RuntimeError(
                    "{} requested to wait for disabled (or missing) module {}".format(
                        analysis_module, wait_exception.analysis
                    )
                )

            # create the dependency between the two analysis modules
            work_item.observable.add_dependency(
                analysis_module.generated_analysis_type,
                analysis_module.instance,
                wait_exception.observable,
                wait_exception.analysis,
                wait_exception.instance,
            )

        except ExcessiveFileDataSizeError:
            raise

        except Exception as e:
            # this is techinically an error but it is going to happen so we log it as a warning
            logging.warning(
                "analysis module {} failed on {} for {} reason {}".format(
                    analysis_module, work_item, root, e
                )
            )
            error_report_path = report_exception()

            if work_item.dependency:
                work_item.dependency.set_status_failed("error: {}".format(e))
                work_item.dependency.increment_status()

            # if analysis failed, copy all the details to error_reports for review
            if get_engine_config().copy_analysis_on_error:
                error_report_stats_dir = None
                if error_report_path and os.path.isdir(root.storage_dir):
                    analysis_dir = "{}.ace".format(error_report_path)
                    try:
                        shutil.copytree(root.storage_dir, analysis_dir)
                        logging.info(
                            "copied analysis from {} to {} for review".format(
                                root.storage_dir, analysis_dir
                            )
                        )
                    except Exception as e:
                        logging.error(
                            "unable to copy from {} to {}: {}".format(
                                root.storage_dir, analysis_dir, e
                            )
                        )

                    try:
                        error_report_stats_dir = os.path.join(analysis_dir, "stats")
                        os.mkdir(error_report_stats_dir)
                    except Exception as e:
                        logging.error(
                            "unable to create error reporting stats dir {}: {}".format(
                                error_report_stats_dir, e
                            )
                        )

            # XXX this logic should not be here
            # were we analyzing a file when we encountered this exception?
            if (
                error_report_path
                and work_item.observable is not None
                and work_item.observable.type == F_FILE
                and get_engine_config().copy_file_on_error
            ):
                target_dir = f"{error_report_path}.files"
                try:
                    os.makedirs(target_dir, exist_ok=True)
                    shutil.copy(work_item.observable.full_path, target_dir)
                except Exception as copy_error:
                    logging.error(f"unable to copy files to {target_dir}: {copy_error}")

        if module_start_time:
            module_end_time = datetime.now()

            # keep track of some module execution time metrics
            if analysis_module.name not in context.total_analysis_time:
                context.total_analysis_time[analysis_module.name] = 0

            context.total_analysis_time[analysis_module.name] += (
                module_end_time - module_start_time
            ).total_seconds()

        # when analyze() executes it populates the work_stack_buffer with things that need to be analyzed
        # if the thing that was just analyzed turned out to be whitelisted (tagged with 'whitelisted')
        # then we stop analyzing this entire analysis tree (the whole thing is considered whitelisted)
        if work_item.observable and work_item.observable.whitelisted:
            logging.info(
                "{} was whitelisted - ignoring {} items on work stack buffer and stopping analysis".format(
                    work_item, len(work_stack_buffer)
                )
            )
            work_stack_buffer.clear()
            context.cancel_analysis()
        else:
            if work_stack_buffer:
                # if an Analysis object was added to the work stack let's go ahead and flush it
                flushed = set()
                for item in work_stack_buffer:
                    if isinstance(item, Analysis):
                        if item in flushed:
                            continue

                        logging.debug("flushing {}".format(item))
                        root.analysis_tree_manager.flush_analysis_details(item)
                        flushed.add(item)

                for buffer_item in work_stack_buffer:
                    work_stack.append(buffer_item)

                work_stack_buffer.clear()

                # if we were in final analysis mode and we added something to the work stack
                # then we exit final analysis mode so that everything can get a chance to execute again
                context.final_analysis_mode = False

    def _execute_recursive_analysis(self, context: AnalysisExecutionContext):
        """Implements the recursive analysis logic of ACE."""

        self._execute_pre_analysis(context)
        self._initialize_work_stack(context)

        assert isinstance(context.root, RootAnalysis)
        assert isinstance(context.work_stack, WorkStack)

        # we use this when we're dealing with delayed analysis
        context.first_pass = True

        # we use this when we're executing in final analysis mode
        context.final_analysis_mode = False

        # when we started analyzing (this time)
        start_time = datetime.now()
        total_analysis_time_seconds = context.root.state["total_analysis_time_seconds"]

        # the last time we logged a warning about analysis taking too long
        context.last_analyze_time_warning = None

        # MAIN LOOP
        # keep going until there is nothing to analyze
        logging.info(
            f"starting analysis on {context.root} with a workload of {len(context.work_stack)}"
        )
        while not context.cancel_analysis_flag:
            # the current WorkTarget
            work_item = None

            # are we done?
            if (
                len(context.work_stack) == 0
                and len(context.root.active_dependencies) == 0
            ):
                # are we in final analysis mode?
                if context.final_analysis_mode:
                    # then we are truly done
                    break

                # should we enter into final analysis mode?
                # we only do this if A) all analysis is complete and B) there is no outstanding delayed analysis
                if not context.root.delayed:
                    logging.info("entering final analysis for {}".format(context.root))
                    context.final_analysis_mode = True
                    # place everything back on the stack
                    for obj in context.root.all:
                        context.work_stack.append(obj)

                    continue

                else:
                    logging.info(
                        "not entering final analysis mode for {} (delayed analysis waiting)".format(
                            context.root
                        )
                    )
                    break

            # get the next thing to analyze
            # if we have delayed analysis then that is the thing to analyze at this moment
            work_item = self._get_delayed_analysis_work_item(context)

            # otherwise check to see if we have any dependencies waiting
            if not work_item:
                work_item = self._get_completed_dependency_work_item(context)

            # otherwise just get the next item off the stack
            if not work_item:
                work_item = self._get_next_work_item(context)

            # otherwise we're done
            if not work_item:
                logging.debug("no work item available")
                continue

            # if there's no observable to analyze then we're done with this work item
            if not work_item.observable:
                logging.debug(f"work item {work_item} has no observable")
                continue

            # check for observable exclusions
            if (
                self._process_observable_exclusions(work_item)
                == ObservableExclusionResult.EXCLUDED
            ):
                continue

            # select the analysis modules we want to use
            analysis_modules = self.get_analysis_modules_for_work_item(
                work_item, context.root.analysis_mode
            )

            logging.debug(f"analyzing {work_item} with {len(analysis_modules)} modules")

            # analyze this thing with the analysis modules we've selected sorted by priority
            for analysis_module in sorted(analysis_modules, key=attrgetter("priority")):
                if context.cancel_analysis_flag:
                    logging.info(f"analysis cancelled for {context.root}")
                    break

                self._execute_module_analysis(
                    context,
                    context.root,
                    work_item,
                    context.work_stack,
                    context.work_stack_buffer,
                    analysis_module,
                    start_time,
                    total_analysis_time_seconds,
                )
