from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, Type, Union

if TYPE_CHECKING:
    from saq.analysis.observable import Observable
    from saq.analysis.analysis import Analysis

class RootAnalysisInterface(Protocol):
    """Interface for root analysis objects."""

    @property
    def state(self) -> Dict[str, Any]:
        """Returns the state dictionary."""
        ...

    @property
    def queue(self) -> str:
        """Returns the queue name."""
        ...

    @property
    def alert_type(self) -> str:
        """Returns the alert type."""
        ...

    @property
    def whitelisted(self) -> bool:
        """Returns True if the entire analysis is whitelisted."""
        ...

    def whitelist(self):
        """Mark the entire analysis as whitelisted."""
        ...

    @property
    def uuid(self) -> str:
        """Returns the UUID of the analysis."""
        ...

    @property
    def storage_dir(self) -> str:
        """Returns the storage directory path."""
        ...

    @property
    def file_dir(self) -> str:
        """Returns the file directory path."""
        ...

    @property
    def event_time(self):
        """Returns the event time."""
        ...

    @event_time.setter
    def event_time(self, value):
        """Set the event time."""
        ...

    @property
    def event_time_datetime(self):
        """Returns the event time as datetime object."""
        ...

    @property
    def analysis_mode(self) -> str:
        """Returns the analysis mode."""
        ...

    @analysis_mode.setter
    def analysis_mode(self, value: str):
        """Set the analysis mode."""
        ...

    @property
    def details(self):
        """Returns the details dictionary."""
        ...

    @details.setter
    def details(self, value):
        """Set the details."""
        ...

    @property
    def all_detection_points(self) -> List:
        """Returns all detection points."""
        ...

    @property
    def all_observables(self) -> List:
        """Returns all observables."""
        ...

    @property
    def all_analysis(self) -> List:
        """Returns all analysis objects."""
        ...

    @property
    def all(self) -> List:
        """Returns all objects in the analysis tree."""
        ...

    def get_observables_by_type(self, o_type: str) -> List:
        """Get observables by type."""
        ...

    def get_analysis_by_type(self, analysis_type: Type) -> List:
        """Get analysis by type."""
        ...

    def find_observables(self, criteria):
        ...

    def find_observable(self, criteria):
        ...

    def create_file_path(self, relative_path: str) -> str:
        ...

    def has_detections(self) -> bool:
        """Returns True if this analysis has detections."""
        ...

    def add_summary_detail(self, *args, **kwargs):
        """Add a summary detail to the analysis."""
        ...

    def add_pivot_link(self, *args, **kwargs):
        """Add a pivot link to the analysis."""
        ...


    def get_action_counter(self, value: str) -> int:
        """Get the action counter value."""
        ...

    def increment_action_counter(self, value: str):
        """Increment the action counter."""
        ...

    def iterate_all_references(self, target: Union["Observable", "Analysis"]):
        """Iterate all references to the target."""
        ...

    @property
    def description(self):
        ...

    @description.setter
    def description(self, value):
        ...

    def set_details_modified(self):
        """Set the details modified flag."""
        ...

    def add_detection_point(self, description, details=None, queue=None,
                            signature_uuid=None, signature_version=None, signature_family=None):
        """Add a detection point to the analysis."""
        ...


class ObservableInterface(Protocol):
    """Interface for observable objects."""

    @property
    def type(self) -> str:
        """Observable type."""
        ...

    @property
    def value(self) -> str:
        """Observable value."""
        ...

    @property
    def time(self) -> Optional[datetime]:
        """Observable time."""
        ...

    @property
    def root(self):
        """Root analysis reference."""
        ...

    def has_directive(self, directive: str) -> bool:
        """Check if observable has directive."""
        ...

    def has_tag(self, tag: str) -> bool:
        """Check if observable has tag."""
        ...

    def get_analysis(self, analysis_type: Type, instance: Optional[str] = None):
        """Get analysis for this observable."""
        ...

    def add_analysis(self, analysis):
        """Add analysis to this observable."""
        ...


class AnalysisInterface(Protocol):
    """Interface for analysis objects."""

    @property
    def completed(self) -> bool:
        """Returns True if analysis is completed."""
        ...

    @completed.setter
    def completed(self, value: bool):
        """Set completion status."""
        ...

    @property
    def delayed(self) -> bool:
        """Returns True if analysis is delayed."""
        ...

    @delayed.setter
    def delayed(self, value: bool):
        """Set delayed status."""
        ...

    @property
    def observables(self) -> List:
        """Returns the observables list."""
        ...

    def add_observable(self, *args, **kwargs):
        """Add an observable to the analysis."""
        ...