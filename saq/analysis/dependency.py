# json dictionary keys
from __future__ import annotations
from typing import Optional

from saq.analysis.observable_registry import ObservableRegistry

KEY_TARGET_OBSERVABLE_ID = "target_observable_id"
KEY_TARGET_ANALYSIS_TYPE = "target_analysis_type"
KEY_SOURCE_OBSERVABLE_ID = "source_observable_id"
KEY_SOURCE_ANALYSIS_TYPE = "source_analysis_type"
KEY_STATUS = "status"
KEY_FAILURE_REASON = "failure_reason"
KEY_RESOLVED = "resolved"

STATUS_READY = "ready"
STATUS_FAILED = "failed"
STATUS_COMPLETED = "completed"
STATUS_RESOLVED = "resolved"


class AnalysisDependency:
    """Represents an dependency between two Analysis objects for a given Observable."""

    def __init__(
        self,
        target_observable_id: str,
        target_analysis_type: str,
        source_observable_id: str,
        source_analysis_type: str,
        observable_registry: ObservableRegistry,
        status=STATUS_READY,
        failure_reason=None,
    ):

        assert isinstance(target_observable_id, str)
        assert isinstance(target_analysis_type, str)
        assert isinstance(source_observable_id, str)
        assert isinstance(source_analysis_type, str)
        assert isinstance(observable_registry, ObservableRegistry)
        assert isinstance(status, str)
        assert failure_reason is None or isinstance(failure_reason, str)

        self.target_observable_id = target_observable_id
        self.target_analysis_type = target_analysis_type
        self.source_observable_id = source_observable_id
        self.source_analysis_type = source_analysis_type
        self.observable_registry = observable_registry
        self.status = status
        self.failure_reason = failure_reason

        # cached references
        self._target_observable = None
        self._target_analysis = None
        self._source_observable = None
        self._source_analysis = None

        self.next: Optional[AnalysisDependency] = (
            None  # the next AnalysisDependency that this one depends on
        )
        self.prev: Optional[AnalysisDependency] = None

    def set_status_failed(self, reason=None):
        self.status = STATUS_FAILED
        self.failure_reason = reason

    def set_status_completed(self):
        self.status = STATUS_COMPLETED

    def set_status_resolved(self):
        self.status = STATUS_RESOLVED

    @property
    def ready(self):
        """Returns True if target analysis has not been completed."""
        return self.status == STATUS_READY

    @property
    def completed(self):
        """Returns True if the target analysis has been completed."""
        return self.status == STATUS_COMPLETED

    @property
    def resolved(self):
        """Returns True if the source analysis has been completed."""
        return self.status == STATUS_RESOLVED

    def increment_status(self):
        if self.status == STATUS_READY:
            self.status = STATUS_COMPLETED
        elif self.status == STATUS_COMPLETED:
            self.status = STATUS_RESOLVED

    @property
    def score(self):
        score = 0
        node = self.next
        while node:
            score += 1
            node = node.next

        return score

    @property
    def failed(self):
        """Returns True if this dependency (or any in the chain of dependencies) has failed."""
        node = self
        while node:
            if node.status == STATUS_FAILED:
                return True

            node = node.next

        return False

    @property
    def delayed(self):
        """Returns True if the source or target analysis (or any in the chain of dependencies) is delayed."""

        source_observable = self.observable_registry.get_by_id(self.source_observable_id)
        if not source_observable:
            raise RuntimeError("source observable {} not found".format(self.source_observable_id))

        source_analysis = self.observable_registry.get_by_id(self.source_observable_id).get_analysis(self.source_analysis_type)
        if source_analysis and source_analysis.delayed:
            return True

        node = self
        while node:
            target_analysis = self.observable_registry.get_by_id(
                node.target_observable_id
            ).get_analysis(node.target_analysis_type)
            if target_analysis and target_analysis.delayed:
                return True

            node = node.next

        return False

    @property
    def json(self):
        return {
            KEY_TARGET_OBSERVABLE_ID: self.target_observable_id,
            KEY_TARGET_ANALYSIS_TYPE: self.target_analysis_type,
            KEY_SOURCE_OBSERVABLE_ID: self.source_observable_id,
            KEY_SOURCE_ANALYSIS_TYPE: self.source_analysis_type,
            KEY_STATUS: self.status,
            KEY_FAILURE_REASON: self.failure_reason,
        }

    @staticmethod
    def from_json(json_dict, observable_registry: ObservableRegistry):
        """Returns a new AnalysisDependency object from the given JSON dict."""
        return AnalysisDependency(
            target_observable_id=json_dict[KEY_TARGET_OBSERVABLE_ID],
            target_analysis_type=json_dict[KEY_TARGET_ANALYSIS_TYPE],
            source_observable_id=json_dict[KEY_SOURCE_OBSERVABLE_ID],
            source_analysis_type=json_dict[KEY_SOURCE_ANALYSIS_TYPE],
            observable_registry=observable_registry,
            status=json_dict[KEY_STATUS],
            failure_reason=json_dict[KEY_FAILURE_REASON],
        )

    def __str__(self):
        return "Analysis Dependency {}({}) --> {}({}) ({}){}".format(
            self.source_analysis_type,
            self.source_observable_id,
            self.target_analysis_type,
            self.target_observable_id,
            self.status,
            (
                " failure reason: {}".format(self.failure_reason)
                if self.failure_reason
                else ""
            ),
        )

    def __repr__(self):
        return self.__str__()

    @property
    def target_observable(self):
        """Returns the target Observable that needs to be analyzed."""
        if self._target_observable:
            return self._target_observable

        self._target_observable = self.observable_registry.get_by_id(self.target_observable_id)
        return self._target_observable

    @property
    def source_observable(self):
        """Returns the Observable that was being analyzed when the request was made."""
        if self._source_observable:
            return self._source_observable

        self._source_observable = self.observable_registry.get_by_id(self.source_observable_id)
        return self._source_observable
