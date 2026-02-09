from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Type, Optional, Union

if TYPE_CHECKING:
    from saq.analysis.observable import Observable
    from saq.analysis.analysis import Analysis


class RootAnalysisAdapter:
    """Adapter that wraps a RootAnalysis to implement RootAnalysisInterface."""

    def __init__(self, root):
        self._root = root

    @property
    def state(self) -> Dict[str, Any]:
        return self._root.state

    @property
    def queue(self) -> str:
        return self._root.queue

    @property
    def alert_type(self) -> str:
        return self._root.alert_type

    @property
    def whitelisted(self) -> bool:
        return self._root.whitelisted

    def whitelist(self):
        self._root.whitelist()

    @property
    def uuid(self) -> str:
        return self._root.uuid

    @property
    def storage_dir(self) -> str:
        return self._root.storage_dir

    @property
    def file_dir(self) -> str:
        return self._root.file_dir

    @property
    def event_time(self):
        return self._root.event_time

    @event_time.setter
    def event_time(self, value):
        self._root.event_time = value

    @property
    def event_time_datetime(self):
        return self._root.event_time_datetime

    @property
    def analysis_mode(self) -> str:
        return self._root.analysis_mode

    @analysis_mode.setter
    def analysis_mode(self, value: str):
        self._root.analysis_mode = value

    @property
    def details(self):
        return self._root.details

    @details.setter
    def details(self, value):
        self._root.details = value

    @property
    def all_detection_points(self) -> List:
        return self._root.all_detection_points

    @property
    def all_observables(self) -> List:
        return self._root.all_observables

    @property
    def all_analysis(self) -> List:
        return self._root.all_analysis

    @property
    def all(self) -> List:
        return self._root.all

    @property
    def description(self) -> str:
        return self._root.description

    @description.setter
    def description(self, value: str):
        self._root.description = value

    def get_observables_by_type(self, o_type: str) -> List:
        return self._root.get_observables_by_type(o_type)

    def get_analysis_by_type(self, analysis_type: Type) -> List:
        return self._root.get_analysis_by_type(analysis_type)

    def find_observable(self, criteria):
        return self._root.find_observable(criteria)

    def find_observables(self, criteria):
        return self._root.find_observables(criteria)

    def create_file_path(self, relative_path: str) -> str:
        return self._root.create_file_path(relative_path)

    def has_detections(self) -> bool:
        return self._root.has_detections()

    def add_summary_detail(self, *args, **kwargs):
        return self._root.add_summary_detail(*args, **kwargs)

    @property
    def observables(self) -> List:
        return self._root.observables

    def add_observable(self, *args, **kwargs):
        return self._root.add_observable(*args, **kwargs)

    def get_action_counter(self, value: str) -> int:
        return self._root.get_action_counter(value)

    def increment_action_counter(self, value: str):
        return self._root.increment_action_counter(value)

    def iterate_all_references(self, target: Union["Observable", "Analysis"]):
        return self._root.iterate_all_references(target)

    def set_details_modified(self):
        return self._root.set_details_modified()

    def add_detection_point(self, description, details=None):
        return self._root.add_detection_point(description, details)

    def has_tag(self, tag: str) -> bool:
        return self._root.has_tag(tag)

    def add_tag(self, tag: str):
        return self._root.add_tag(tag)

    @property
    def tags(self) -> list:
        return self._root.tags


class ObservableAdapter:
    """Adapter that wraps an Observable to implement ObservableInterface."""

    def __init__(self, observable):
        self._observable = observable

    @property
    def type(self) -> str:
        return self._observable.type

    @property
    def value(self) -> str:
        return self._observable.value

    @property
    def time(self) -> Optional[datetime]:
        return self._observable.time

    @property
    def root(self):
        return self._observable.root

    def has_directive(self, directive: str) -> bool:
        return self._observable.has_directive(directive)

    def has_tag(self, tag: str) -> bool:
        return self._observable.has_tag(tag)

    def get_analysis(self, analysis_type: Type, instance: Optional[str] = None):
        return self._observable.get_analysis(analysis_type, instance)

    def add_analysis(self, analysis):
        return self._observable.add_analysis(analysis)


class AnalysisAdapter:
    """Adapter that wraps an Analysis to implement AnalysisInterface."""

    def __init__(self, analysis):
        self._analysis = analysis

    @property
    def completed(self) -> bool:
        return self._analysis.completed

    @completed.setter
    def completed(self, value: bool):
        self._analysis.completed = value

    @property
    def delayed(self) -> bool:
        return self._analysis.delayed

    @delayed.setter
    def delayed(self, value: bool):
        self._analysis.delayed = value

    @property
    def observables(self) -> List:
        return self._analysis.observables

    def add_observable(self, *args, **kwargs):
        return self._analysis.add_observable(*args, **kwargs)