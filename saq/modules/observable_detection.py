import logging
from typing import override

from saq.analysis import Analysis
from saq.signatures import OBSERVABLE_FLAGGED
from saq.constants import REDIS_DB_FOR_DETECTION_A, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.export.redis_cache import REDIS_CONFIG_NAME
from saq.redis_client import get_redis_connection

KEY_FOR_DETECTION = "for_detection"

class ObservableDetectionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_FOR_DETECTION: False,
        }

    @override
    @property
    def display_name(self) -> str:
        return "Observable Detection Analysis"

    @property
    def for_detection(self) -> bool:
        return self.details[KEY_FOR_DETECTION]

    @for_detection.setter
    def for_detection(self, value: bool):
        self.details[KEY_FOR_DETECTION] = value

    def generate_summary(self):
        # Only generate a summary if the observable is enabled for detection
        if self.for_detection:
            return f"{self.display_name}: enabled for detection"
        else:
            return None


class ObservableDetectionAnalyzer(AnalysisModule):
    """Checks if any observable is enabled for detection and, if so, will add a detection point."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._redis_connection = None

    @property
    def generated_analysis_type(self):
        return ObservableDetectionAnalysis

    @property
    def valid_observable_types(self):
        # None here denotes that it will run on all observable types
        return None

    @property
    def redis_connection(self):
        """The connection to the cache `ace observables export` maintains.

        Built once per module instance rather than once per observable: this module runs against
        every observable of every type, and each redis.Redis carries its own connection pool, so
        constructing one per call meant a TCP connect plus AUTH and SELECT for every observable in
        every alert. get_redis_connection sets health_check_interval, which handles reconnecting on
        a long-lived worker.
        """
        if self._redis_connection is None:
            self._redis_connection = get_redis_connection(
                database=REDIS_DB_FOR_DETECTION_A, config_name=REDIS_CONFIG_NAME)

        return self._redis_connection

    def execute_analysis(self, observable, **kwargs) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        assert isinstance(analysis, ObservableDetectionAnalysis)

        # tests inject a fake connection through this
        redis_connection = kwargs.get("redis_connection", None) or self.redis_connection

        if redis_connection.get(f"{observable.type}:{observable.value}"):
            logging.info(f"observable {observable.type}:{observable.value} is enabled for detection")
            analysis.for_detection = True
            observable.add_detection_point(f"Observable {observable.type}:{observable.value} is enabled for detection", signature_uuid=OBSERVABLE_FLAGGED.uuid)
            observable.add_tag(f"detect_{observable.type}")
        else:
            logging.debug(f"observable {observable.type}:{observable.value} is not enabled for detection")

        return AnalysisExecutionResult.COMPLETED