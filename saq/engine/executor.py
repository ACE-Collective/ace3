from datetime import datetime, UTC
import logging
from operator import attrgetter
import os
import shutil
import threading
import time
from typing import Optional, Union
from enum import Enum

import iptools
from saq.analysis.analysis import Analysis
from saq.analysis.blob_store import get_blob_store
from saq.analysis.cache import (
    apply_delta,
    generate_cache_key,
    get_cached_delta,
    put_cached_delta,
)
from saq.analysis.errors import ExcessiveFileDataSizeError
from saq.analysis.module_execution_delta import (
    ModuleExecutionDelta,
    merge_module_execution_deltas,
)
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.analysis.snapshot import ModuleExecutionSnapshot
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
    F_IP,
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
        # Per-(root, module) aggregates surfaced on the per-root metrics event.
        # Keyed by module.name; default 0 when absent.
        self.total_exec_count: dict[str, int] = {}
        self.cache_hit_count: dict[str, int] = {}
        self.cache_miss_count: dict[str, int] = {}
        # the cache is append-only — every write is an insert
        self.cache_write_count_insert: dict[str, int] = {}
        self.cache_lookup_ms_sum: dict[str, int] = {}
        self.cache_lookup_ms_max: dict[str, int] = {}
        # lookup_ms decomposed: key_ms is the (separately measured) cache-key /
        # tool-probe cost; db/decode/blob sum to lookup_ms.
        self.cache_lookup_key_ms_sum: dict[str, int] = {}
        self.cache_lookup_db_ms_sum: dict[str, int] = {}
        self.cache_lookup_decode_ms_sum: dict[str, int] = {}
        self.cache_lookup_blob_ms_sum: dict[str, int] = {}
        self.cache_write_ms_sum: dict[str, int] = {}
        self.cache_write_ms_max: dict[str, int] = {}
        self.cache_write_bytes_uncompressed_sum: dict[str, int] = {}
        self.cache_write_bytes_compressed_sum: dict[str, int] = {}
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

    def record_cache_lookup(self, module_name: str, result) -> None:
        """Accumulate a cache lookup's latency into the per-module aggregates.

        Called for BOTH hits and misses (a miss's lookup time is pure overhead
        on top of the live run — see the cache-miss handling in the executor).
        ``result`` is a ``CacheLookupResult``; ``lookup_ms`` gets both a sum and
        a max, the four components only sums (they drive the per-component
        averages the payoff panel breaks lookup cost down by).
        """
        self.cache_lookup_ms_sum[module_name] = (
            self.cache_lookup_ms_sum.get(module_name, 0) + result.lookup_ms
        )
        self.cache_lookup_ms_max[module_name] = max(
            self.cache_lookup_ms_max.get(module_name, 0), result.lookup_ms
        )
        self.cache_lookup_key_ms_sum[module_name] = (
            self.cache_lookup_key_ms_sum.get(module_name, 0) + result.key_ms
        )
        self.cache_lookup_db_ms_sum[module_name] = (
            self.cache_lookup_db_ms_sum.get(module_name, 0) + result.db_ms
        )
        self.cache_lookup_decode_ms_sum[module_name] = (
            self.cache_lookup_decode_ms_sum.get(module_name, 0) + result.decode_ms
        )
        self.cache_lookup_blob_ms_sum[module_name] = (
            self.cache_lookup_blob_ms_sum.get(module_name, 0) + result.blob_ms
        )

    def record_execution_statistics(self, elapsed_time: float, stats_dir: str):
        """Records the execution statistics for the analysis.

        Emits one fluent-bit event per (root, module) pair where the module
        had any activity in this execution context — either live execution
        time, cache hits, cache misses, or cache writes. Each event carries
        the per-module aggregates (exec_count, cache_* counters, byte/time
        sums) and root-level context (alert_type, is_alert, queue).

        Args:
            elapsed_time: The total elapsed time for the analysis.
            stats_dir: The (base) directory to save the statistics to (typically g(G_MODULE_STATS_DIR)).
        """
        try:
            engine_config = get_engine_config()
            if not engine_config.metrics_logging.enabled:
                return

            fluent_bit_sender = sender.FluentSender(
                engine_config.metrics_logging.fluent_bit_tag,
                host=engine_config.metrics_logging.fluent_bit_hostname,
                port=engine_config.metrics_logging.fluent_bit_port)

            current_time = local_time().strftime("%Y-%m-%d %H:%M:%S.%f")
            _total = sum(self.total_analysis_time.values())

            # Iterate the union of all per-(root, module) counter dicts so
            # cache-only modules (cache hits, no live executions) still get
            # a row.
            all_module_keys = (
                set(self.total_analysis_time.keys())
                | set(self.total_exec_count.keys())
                | set(self.cache_hit_count.keys())
                | set(self.cache_miss_count.keys())
                | set(self.cache_write_count_insert.keys())
            )

            for key in all_module_keys:
                analysis_time = self.total_analysis_time.get(key, 0.0)
                percentage = 0.0
                if elapsed_time:
                    percentage = (analysis_time / elapsed_time) * 100.0
                if not elapsed_time:
                    elapsed_time = 0

                payload = {
                    "timestamp": current_time,
                    "module": key,
                    "analysis_time_seconds": analysis_time,
                    "percentage": percentage,
                    "total_analysis_time_seconds": _total,
                    "total_time_seconds": elapsed_time,
                    "root_uuid": self.root.uuid,
                    "exec_count": self.total_exec_count.get(key, 0),
                    "alert_type": self.root.alert_type,
                    "is_alert": self.root.analysis_mode == ANALYSIS_MODE_CORRELATION,
                    "queue": self.root.queue,
                }

                hits = self.cache_hit_count.get(key, 0)
                misses = self.cache_miss_count.get(key, 0)
                inserts = self.cache_write_count_insert.get(key, 0)
                if hits or misses or inserts:
                    payload["cache_hit_count"] = hits
                    payload["cache_miss_count"] = misses
                    payload["cache_write_count_insert"] = inserts
                    # lookup latency covers ALL lookups (hits + misses) —
                    # misses' lookup time is the cache's pure overhead.
                    if hits or misses:
                        payload["cache_lookup_ms_sum"] = self.cache_lookup_ms_sum.get(key, 0)
                        payload["cache_lookup_ms_max"] = self.cache_lookup_ms_max.get(key, 0)
                        # lookup_ms decomposed: db+decode+blob sum to lookup_ms;
                        # key_ms is the separate cache-key/tool-probe cost.
                        payload["cache_lookup_key_ms_sum"] = self.cache_lookup_key_ms_sum.get(key, 0)
                        payload["cache_lookup_db_ms_sum"] = self.cache_lookup_db_ms_sum.get(key, 0)
                        payload["cache_lookup_decode_ms_sum"] = self.cache_lookup_decode_ms_sum.get(key, 0)
                        payload["cache_lookup_blob_ms_sum"] = self.cache_lookup_blob_ms_sum.get(key, 0)
                    if inserts:
                        payload["cache_write_ms_sum"] = self.cache_write_ms_sum.get(key, 0)
                        payload["cache_write_ms_max"] = self.cache_write_ms_max.get(key, 0)
                        payload["cache_write_bytes_uncompressed_sum"] = (
                            self.cache_write_bytes_uncompressed_sum.get(key, 0)
                        )
                        payload["cache_write_bytes_compressed_sum"] = (
                            self.cache_write_bytes_compressed_sum.get(key, 0)
                        )

                fluent_bit_sender.emit(None, payload)

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

        # the AnalysisExecutionContext for the analysis currently running in execute(), or None.
        self._current_context: Optional[AnalysisExecutionContext] = None

    def cancel_current_analysis(self):
        """Cancel the analysis currently running in execute(), if any."""
        context = self._current_context
        if context is not None:
            logging.warning("cancelling in-flight analysis for %s", context.root)
            context.cancel_analysis()

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

        # expose it so cancel_current_analysis() can reach it while this analysis runs
        self._current_context = context

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
        logging_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(filename)s:%(lineno)d] [%(threadName)s] [%(process)d] [%(levelname)s] - %(message)s"
        ))
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
            # this analysis is no longer running -- nothing left to cancel
            self._current_context = None

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
            if work_item.observable.type in [ F_IP, F_IPV4 ]:
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

    def _apply_cached_delta(
        self,
        context: "AnalysisExecutionContext",
        root: RootAnalysis,
        observable: Observable,
        module: AnalysisModuleInterface,
        lookup_result,
    ) -> None:
        """Replay a cached delta and record cache-hit attribution + metrics.

        Calls ``apply_delta`` to mutate the tree, then appends a
        ``from_cache_hit=True`` copy of the delta to
        ``root._module_executions`` for audit. Always records — the
        ``is_empty`` filter that Phase 1 uses for live captures does NOT
        apply here, because cache consultation is itself information
        worth keeping.

        ``lookup_result`` is the ``CacheLookupResult`` from
        ``get_cached_delta``; ``lookup_result.lookup_ms`` is the wall time the
        caller spent there (DB SELECT + zstd decompress + deserialize + any
        blob fetch). Combined with ``replay_ms`` it gives the total cost of a
        hit — for cheap modules like whois the lookup is the larger half, so
        ``replay_ms`` alone would understate it.

        Bumps ``context.cache_hit_count`` and the lookup latency
        accumulators so the per-(root, module) metrics emitted at root
        completion reflect this hit. Replaces the prior ``"analysis cache
        hit"`` plain log — that data is now aggregated into the per-root
        summary event.

        ``monitor`` and ``track_current_analysis_module`` are skipped on
        purpose: both are bounded by live module wall time, and replay
        completes in milliseconds.
        """
        delta = lookup_result.delta
        replay_start_ns = time.monotonic_ns()
        apply_delta(root, observable, delta, blob_store=get_blob_store())
        replay_ms = (time.monotonic_ns() - replay_start_ns) // 1_000_000

        attribution_delta = delta.with_cache_hit_metadata(
            executed_at=datetime.now(UTC),
            execution_time_ms=lookup_result.lookup_ms + replay_ms,
            root_uuid=root.uuid,
            observable_uuid=observable.uuid,
        ).without_analysis_details()
        root.record_module_execution(attribution_delta)

        module_name = module.config.name
        context.cache_hit_count[module_name] = (
            context.cache_hit_count.get(module_name, 0) + 1
        )
        context.record_cache_lookup(module_name, lookup_result)

        # Best-effort hit-time hook: lets a module emit telemetry from the
        # replayed analysis (e.g. phishkit's saved bytes). Must never break
        # replay, so failures are swallowed.
        try:
            module.on_cache_hit(root, observable)
        except Exception:
            logging.warning(
                "on_cache_hit failed module_name=%s observable_uuid=%s",
                module_name, observable.uuid, exc_info=True,
            )

    def _maybe_write_cache_delta(
        self,
        context: "AnalysisExecutionContext",
        root: RootAnalysis,
        observable: Observable,
        analysis_module: AnalysisModuleInterface,
        delta: ModuleExecutionDelta,
        analysis_result: AnalysisExecutionResult,
        prior_deltas: list[ModuleExecutionDelta],
    ) -> None:
        """Phase 2 cache write, best-effort — a failure here must never
        prevent ``root.save()``.

        Gates:

        - module opted in (``cache_ttl``) and the cache globally enabled;
        - ``analysis_result`` is COMPLETED. A delayed-analysis module
          returns INCOMPLETE for every mid-delay cycle; without this gate
          a non-empty intermediate delta whose ``analysis`` dict is None
          (the slot already existed, no delayed→completed transition)
          slips past ``put_cached_delta``'s still-delayed check — which
          inspects the analysis dict — and a partial result gets cached.

        ``prior_deltas`` are the earlier delayed-cycle deltas recorded for
        this (module_path, observable); their tree mutations are merged
        into the cached delta so a replay reproduces the pre-delay
        contribution too. Removal refusal is evaluated by
        ``put_cached_delta`` on the *merged* delta — a cycle-1 removal
        refuses the whole write.
        """
        if analysis_module.cache_ttl is None:
            return
        if analysis_result != AnalysisExecutionResult.COMPLETED:
            return
        if not get_config().analysis_cache.enabled:
            return

        try:
            cache_delta = delta
            if prior_deltas:
                cache_delta = merge_module_execution_deltas(prior_deltas, delta)
            # root is required for Phase 4 file-observable deltas — the
            # produced files' bytes are read from this root's file dir into
            # the blob store.
            write_result = put_cached_delta(
                cache_delta, analysis_module, get_blob_store(), root=root,
            )
            if write_result is not None:
                module_name = analysis_module.name
                context.cache_write_count_insert[module_name] = (
                    context.cache_write_count_insert.get(module_name, 0) + 1
                )
                context.cache_write_ms_sum[module_name] = (
                    context.cache_write_ms_sum.get(module_name, 0)
                    + write_result.write_ms
                )
                context.cache_write_ms_max[module_name] = max(
                    context.cache_write_ms_max.get(module_name, 0),
                    write_result.write_ms,
                )
                context.cache_write_bytes_uncompressed_sum[module_name] = (
                    context.cache_write_bytes_uncompressed_sum.get(module_name, 0)
                    + write_result.uncompressed_bytes
                )
                context.cache_write_bytes_compressed_sum[module_name] = (
                    context.cache_write_bytes_compressed_sum.get(module_name, 0)
                    + write_result.compressed_bytes
                )
        except Exception:
            logging.warning(
                "failed to write analysis cache module_name=%s "
                "observable_uuid=%s",
                analysis_module.config.name, observable.uuid,
                exc_info=True,
                extra={
                    "module_name": analysis_module.config.name,
                    "observable_uuid": observable.uuid,
                },
            )

    def _seed_declared_dependencies(
        self, work_item: WorkTarget, analysis_module: AnalysisModuleInterface
    ) -> bool:
        """Ensure this module's declared dependencies are satisfied before it runs.

        For each declared dependency module that is not yet satisfied on this
        observable, seed the same dependency edge the WaitForAnalysisException
        handler would create (observable.add_dependency), so the existing
        dependency-resolution loop runs the dependency first and re-queues this
        module. Returns True if any dependency was unmet and this module should be
        deferred to a later pass; False if all declared dependencies are satisfied
        and the module may run now.

        A dependency is treated as satisfied (mirroring wait_for_analysis) when the
        dependency module does not accept the observable, an existing dependency edge
        is completed/resolved/failed, or the target analysis is already present as a
        completed Analysis or the "no analysis" (False) sentinel. A present-but-not-
        completed (delayed) target analysis is NOT satisfied -- we keep waiting.
        """
        dependency_modules = self.configuration_manager.get_declared_dependencies(
            analysis_module.config.name
        )
        if not dependency_modules:
            return False

        observable = work_item.observable
        unmet = False
        for dependency_module in dependency_modules:
            # a dependency that would never analyze this observable is vacuously satisfied
            if not dependency_module.accepts(observable):
                continue

            dep = observable.get_dependency(
                MODULE_PATH(
                    dependency_module.generated_analysis_type,
                    instance=dependency_module.instance,
                )
            )
            # an existing edge already driven to a terminal state satisfies the dependency
            if dep and (dep.completed or dep.resolved or dep.failed):
                continue

            existing_analysis = observable.get_analysis(
                dependency_module.generated_analysis_type,
                instance=dependency_module.instance,
            )
            # satisfied if we have a completed Analysis or the False no-analysis sentinel
            if existing_analysis is not None and not (
                isinstance(existing_analysis, Analysis)
                and not existing_analysis.completed
            ):
                continue

            # unmet -- seed the dependency edge (idempotent; add_dependency dedups)
            observable.add_dependency(
                analysis_module.generated_analysis_type,
                analysis_module.instance,
                observable,
                dependency_module.generated_analysis_type,
                dependency_module.instance,
            )
            unmet = True

        if unmet:
            # if we are re-running the source of a completed dependency but still have
            # another unmet dependency, consume that completed dependency so it is not
            # re-selected
            if work_item.dependency and work_item.dependency.completed:
                work_item.dependency.increment_status()
            return True

        return False

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

        # ensure declared dependencies are satisfied before running this module;
        # if any are unmet, the dependency edges are seeded and we defer this module
        if self._seed_declared_dependencies(work_item, analysis_module):
            return

        try:
            # custom_requirement is the final gate before the module runs. it is
            # evaluated here (rather than in accepts()) so that it runs only after
            # this module's declared dependencies are satisfied -- letting it inspect
            # dependency results and, by raising WaitForAnalysisException (directly or
            # via wait_for_analysis), wait on a cross-observable analysis. a raised
            # WaitForAnalysisException is intentionally not caught here; it propagates
            # to the handler below which seeds the dependency edge.
            try:
                if not analysis_module.custom_requirement(work_item.observable):
                    logging.debug(
                        "%s does not pass custom requirements for %s",
                        work_item.observable, analysis_module,
                    )
                    # skip WITHOUT recording a no-analysis sentinel so this module is
                    # re-considered on a later pass (e.g. once a directive lands). when
                    # this work item is resolving a dependency edge we still resolve it
                    # here (no analysis was produced) exactly as _process_generated_analysis
                    # would -- failing the edge and re-queuing the waiting source so it is
                    # re-analyzed in the normal (not final-analysis) phase.
                    if work_item.dependency:
                        if work_item.dependency.ready:
                            work_item.dependency.set_status_failed("custom requirement not met")
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
                        elif work_item.dependency.completed:
                            work_item.dependency.increment_status()
                    return
            except NotImplementedError:
                # module does not override custom_requirement -- no custom gate
                pass

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

            # Phase 3: cache-hit short-circuit. By the time we reach this
            # branch, accepts() has already returned True, which means the
            # observable has no analysis at this module_path. Cache replay
            # therefore does not conflict with a pre-existing slot. The
            # inner try/except deliberately does NOT re-raise — replay
            # failure must fall through to the live path so the outer
            # except Exception below doesn't treat it as a module failure
            # (which would call report_exception() spuriously).
            if (
                analysis_module.cache_ttl is not None
                and get_config().analysis_cache.enabled
            ):
                try:
                    lookup_result = get_cached_delta(
                        work_item.observable, analysis_module, get_blob_store()
                    )
                    if lookup_result.delta is not None:
                        self._apply_cached_delta(
                            context, root, work_item.observable, analysis_module,
                            lookup_result,
                        )
                        self._process_generated_analysis(
                            AnalysisExecutionResult.COMPLETED, root, work_item,
                            work_stack, work_stack_buffer, analysis_module,
                        )
                        root.save()
                        return
                    elif lookup_result.miss_reason is not None:
                        # Real cache miss (DB lookup happened, no usable row).
                        # Falls through to live execution below; bump the
                        # per-(root, module) miss counter for end-of-root metrics.
                        # Lookup latency is accumulated on misses too — a miss's
                        # lookup time is pure overhead on top of the live run,
                        # and it's exactly what the lookup-cost-vs-live-cost
                        # payoff comparison needs. cache_lookup_ms_* therefore
                        # covers ALL lookups (hits + misses), not hits only.
                        module_name = analysis_module.name
                        context.cache_miss_count[module_name] = (
                            context.cache_miss_count.get(module_name, 0) + 1
                        )
                        context.record_cache_lookup(module_name, lookup_result)
                except Exception:
                    logging.warning(
                        "cache replay failed module_name=%s observable_uuid=%s "
                        "— falling through to live run",
                        analysis_module.config.name, work_item.observable.uuid,
                        exc_info=True,
                        extra={
                            "module_name": analysis_module.config.name,
                            "observable_uuid": work_item.observable.uuid,
                            "observable_type": work_item.observable.type,
                        },
                    )
                    # Intentional: do not return, do not re-raise.

            # delayed_analysis=True must only be passed to the module that is actually
            # being resumed from its prior delay_analysis() call -- not to every module
            # invoked during a DelayedAnalysisRequest resumption. context.is_delayed_analysis
            # is context-wide and would otherwise route unrelated modules with persisted
            # incomplete analyses (e.g. two-phase modules like ObservableModifierAnalyzer)
            # into continue_analysis(), which they do not implement.
            is_resuming_delayed_module = (
                context.delayed_analysis_request is not None
                and work_item.analysis_module is context.delayed_analysis_request.analysis_module
            )

            logging.debug(
                "analyzing {} with {} (final analysis={}) (delayed analysis={})".format(
                    work_item.observable, analysis_module, context.final_analysis_mode, is_resuming_delayed_module
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

                # snapshot before module execution for delta tracking
                snapshot_before = None
                try:
                    wide_diff = getattr(analysis_module.config, 'wide_diff', False)
                    if wide_diff:
                        snapshot_before = ModuleExecutionSnapshot.wide(root, work_item.observable, analysis_module)
                    else:
                        snapshot_before = ModuleExecutionSnapshot.narrow(root, work_item.observable, analysis_module)
                except Exception:
                    logging.warning(
                        "failed to capture pre-execution snapshot module_name=%s "
                        "observable_uuid=%s",
                        analysis_module.config.name, work_item.observable.uuid,
                        exc_info=True,
                        extra={
                            "module_name": analysis_module.config.name,
                            "observable_uuid": work_item.observable.uuid,
                        },
                    )
                delta_start_ns = time.monotonic_ns()

                # if the analysis module has specified a semaphore name in the configuration
                # then we need to acquire the semaphore before analyzing
                if analysis_module.semaphore_name is not None:
                    with NetworkSemaphore(analysis_module.semaphore_name):
                        analysis_result = analysis_module.analyze(
                            work_item.observable, context.final_analysis_mode, is_resuming_delayed_module
                        )
                else:
                    analysis_result = analysis_module.analyze(
                        work_item.observable, context.final_analysis_mode, is_resuming_delayed_module
                    )

                # snapshot after and compute delta — wrapped in try/except so
                # delta recording failures never prevent root.save()
                if snapshot_before is not None:
                    try:
                        if wide_diff:
                            snapshot_after = ModuleExecutionSnapshot.wide(root, work_item.observable, analysis_module)
                        else:
                            snapshot_after = ModuleExecutionSnapshot.narrow(root, work_item.observable, analysis_module)
                        delta = ModuleExecutionSnapshot.diff(snapshot_before, snapshot_after, analysis_module, work_item.observable, is_resuming_delayed_module)
                        delta.execution_time_ms = (time.monotonic_ns() - delta_start_ns) // 1_000_000

                        # Compute the cache key before recording: the recorded
                        # entry is a details-stripped *copy* of this delta, so
                        # anything assigned to the original afterwards would be
                        # missing from root.json. Key-generation failure
                        # (extended_version probing can stat files) must not
                        # block recording.
                        if (
                            analysis_module.cache_ttl is not None
                            and get_config().analysis_cache.enabled
                        ):
                            try:
                                delta.cache_key = generate_cache_key(work_item.observable, analysis_module)
                            except Exception:
                                logging.warning(
                                    "failed to generate cache key module_name=%s "
                                    "observable_uuid=%s",
                                    analysis_module.config.name, work_item.observable.uuid,
                                    exc_info=True,
                                    extra={
                                        "module_name": analysis_module.config.name,
                                        "observable_uuid": work_item.observable.uuid,
                                    },
                                )

                        # Prior delayed-cycle deltas for this (module_path,
                        # observable): their tree mutations are missing from
                        # this final cycle's diff but must be part of the
                        # cached delta (merged in _maybe_write_cache_delta).
                        # Collected BEFORE recording so the just-recorded
                        # copy of this delta can't match the filter. The
                        # analysis-is-None-or-delayed condition excludes a
                        # previous *completed* run's delta surviving analyst
                        # re-analysis (root._reset() keeps _module_executions).
                        prior_deltas = []
                        if is_resuming_delayed_module:
                            prior_deltas = [
                                d for d in root.module_executions
                                if d.module_path == delta.module_path
                                and d.observable_uuid == delta.observable_uuid
                                and not d.from_cache_hit
                                and (d.analysis is None or d.analysis.get("delayed"))
                            ]

                        if not delta.is_empty:
                            # The attribution log doesn't need the bulk
                            # analysis.details payload — the analysis tree
                            # persists details once already. The cache write
                            # below uses the original delta, which keeps them.
                            root.record_module_execution(delta.without_analysis_details())

                        if delta.has_removals:
                            logging.info(
                                "module produced removals in delta module_name=%s "
                                "observable_uuid=%s",
                                analysis_module.config.name, work_item.observable.uuid,
                                extra={
                                    "module_name": analysis_module.config.name,
                                    "observable_uuid": work_item.observable.uuid,
                                    "observable_type": work_item.observable.type,
                                },
                            )

                        self._maybe_write_cache_delta(
                            context, root, work_item.observable, analysis_module,
                            delta, analysis_result, prior_deltas,
                        )
                    except Exception:
                        logging.warning(
                            "failed to record module execution delta module_name=%s "
                            "observable_uuid=%s",
                            analysis_module.config.name, work_item.observable.uuid,
                            exc_info=True,
                            extra={
                                "module_name": analysis_module.config.name,
                                "observable_uuid": work_item.observable.uuid,
                            },
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

        except AnalysisFailedException as e:
            # Expected when work is retried after a previous execution was killed - skip
            # error report since this is not an unexpected failure
            logging.warning(
                "skipping observable that failed in previous execution: module %s on %s for %s: %s",
                analysis_module, work_item, root, e,
            )
            if work_item.dependency:
                work_item.dependency.set_status_failed("error: {}".format(e))
                work_item.dependency.increment_status()

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
            # Count every invocation including delayed-analysis retries
            # (each retry is a real call with real wall time).
            context.total_exec_count[analysis_module.name] = (
                context.total_exec_count.get(analysis_module.name, 0) + 1
            )

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
