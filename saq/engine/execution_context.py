from datetime import datetime
import logging
from typing import TYPE_CHECKING, Optional, Union

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_engine_config
from saq.constants import ANALYSIS_MODE_CORRELATION
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.util import local_time

from fluent import sender

if TYPE_CHECKING:
    from saq.engine.work_stack import WorkStack, WorkTarget


class EngineExecutionContext:
    """All of the runtime state for a single work item.

    There is exactly one of these per work item. The Worker builds it the moment
    it claims the item and every layer below -- AnalysisOrchestrator,
    AnalysisExecutor and the recursive analysis algorithm -- shares that one
    object. That matters most for cancellation: the cancel flag has to be
    readable from the moment the item is claimed, not just once the executor's
    main loop is running.
    """

    def __init__(self, work_item: Union[RootAnalysis, DelayedAnalysisRequest]):
        """Initialize the execution context with a work item."""
        assert isinstance(work_item, RootAnalysis) or isinstance(
            work_item, DelayedAnalysisRequest
        )

        self.work_item: Union[RootAnalysis, DelayedAnalysisRequest] = work_item

        # this is set to True to cancel the analysis
        self._cancel_analysis_flag: bool = False

        # set True when analysis was aborted (e.g. timeout / exception) and its outstanding
        # delayed-analysis requests were cleared, meaning root.delayed is now stale and no
        # follow-up pass will rebuild the observable index
        self.analysis_aborted: bool = False

        # set True when no analysis ran at all for this work item because the alert was
        # already dispositioned. Nothing in the tree changed, so there is nothing to sync.
        self.analysis_skipped: bool = False

        # we keep track of the total amount of time (in seconds) that each module takes
        # key = module.name, value = total_seconds
        self.total_analysis_time: dict = {}

        # Per-(root, module) aggregates surfaced on the per-root metrics event.
        # Keyed by module.name; default 0 when absent.
        self.total_exec_count: dict[str, int] = {}
        self.cache_hit_count: dict[str, int] = {}
        self.cache_miss_count: dict[str, int] = {}
        # the cache is append-only -- every write is an insert
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

        # state of the recursive analysis algorithm
        self.work_stack: Optional["WorkStack"] = None
        self.work_stack_buffer: Optional[list["WorkTarget"]] = None
        self.first_pass: bool = True
        self.last_disposition_check: datetime = datetime.now()
        # when the in-flight tree was last written to disk by AnalysisExecutor._save_root.
        # only meaningful for analysis modes that set root_save_frequency
        self.last_root_save: datetime = datetime.now()
        self.final_analysis_mode: bool = False
        self.last_analyze_time_warning: Optional[datetime] = None

    @property
    def root(self) -> Optional[RootAnalysis]:
        """Returns the RootAnalysis object the current process is analyzing.

        This is deliberately derived rather than captured. The context exists
        before the work item has been loaded, and DelayedAnalysisRequest.load()
        *constructs* the RootAnalysis -- a value snapshotted in __init__ would be
        None for the entire life of a delayed-analysis pass.
        """
        return self.work_item if isinstance(self.work_item, RootAnalysis) else self.work_item.root

    @property
    def delayed_analysis_request(self) -> Optional[DelayedAnalysisRequest]:
        """Returns the DelayedAnalysisRequest object the current process is analyzing."""
        return self.work_item if isinstance(self.work_item, DelayedAnalysisRequest) else None

    @property
    def is_delayed_analysis(self) -> bool:
        """Returns True if the work item is a delayed analysis request."""
        return self.delayed_analysis_request is not None

    @property
    def cancel_analysis_flag(self) -> bool:
        """Returns True if analysis has been cancelled."""
        return self._cancel_analysis_flag

    def cancel_analysis(self):
        """Sends a signal to cancel the analysis."""
        self._cancel_analysis_flag = True

    def record_cache_lookup(self, module_name: str, result) -> None:
        """Accumulate a cache lookup's latency into the per-module aggregates.

        Called for BOTH hits and misses (a miss's lookup time is pure overhead
        on top of the live run -- see the cache-miss handling in the executor).
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
        had any activity in this execution context -- either live execution
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
                    # lookup latency covers ALL lookups (hits + misses) --
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
