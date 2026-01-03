import logging
import sys
from typing import TYPE_CHECKING, Callable, Iterable, List, Optional, Type, Union

from saq.analysis.analysis import Analysis
from saq.analysis.analysis_tree.analysis_tree_analytics import AnalysisTreeAnalytics
from saq.analysis.analysis_tree.analysis_tree_persistence import AnalysisTreePersistenceManager
from saq.analysis.analysis_tree.analysis_tree_query import AnalysisTreeQueryEngine
from saq.analysis.analysis_tree.analysis_tree_validator import AnalysisTreeValidator
from saq.analysis.dependency_manager import AnalysisDependencyManager
from saq.analysis.event_bus import AnalysisEventBus
from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.analysis.observable_registry import ObservableRegistry
from saq.analysis.detection_point import DetectionPoint
from saq.constants import EVENT_ANALYSIS_ADDED, EVENT_OBSERVABLE_ADDED

if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis

class AnalysisTreeManager:
    """Manages the analysis tree of a RootAnalysis object.

    - Allows adding Analysis and Observable objects.
    - Provides an interface to query the analysis tree."""

    def __init__(
        self, 
        event_bus: AnalysisEventBus, 
        file_manager: FileManagerInterface,
        root_analysis: "RootAnalysis"
    ):
        """Initialize the AnalysisTreeManager.

        Args:
            event_bus: The AnalysisEventBus instance
            file_manager: The FileManagerInterface instance
            root_analysis: The RootAnalysis instance this manager belongs to
        """
        # this gets set once and cannot be changed
        self.observable_registry = ObservableRegistry()
        self.dependency_manager = AnalysisDependencyManager(self.observable_registry)
        self.event_bus = event_bus
        self.file_manager = file_manager
        self.root_analysis = root_analysis
        
        # Initialize the query engine
        self.query_engine = AnalysisTreeQueryEngine(root_analysis, self.observable_registry)
        
        # Initialize the analytics engine
        self.analytics = AnalysisTreeAnalytics(root_analysis, self.query_engine)
        
        # Initialize the validator
        self.validator = AnalysisTreeValidator(self.query_engine, self.observable_registry)
        
        # Initialize the persistence manager
        self.persistence_manager = AnalysisTreePersistenceManager(
            file_manager, 
            root_analysis, 
            self.observable_registry,
            self.dependency_manager,
            self.query_engine
        )

    # query engine facade
    # ------------------------------------------------------------------------

    def get_observable_by_id(self, uuid: str) -> Optional[Observable]:
        """Returns the Observable object for the given uuid."""
        return self.query_engine.get_observable_by_id(uuid)

    @property
    def all_analysis(self) -> list[Analysis]:
        """Returns the list of all Analysis performed for this Alert."""
        return self.query_engine.all_analysis

    @property
    def all_non_root_analysis(self) -> list[Analysis]:
        """Returns the list of all Analysis performed for this Alert."""
        return self.query_engine.all_non_root_analysis

    @property
    def all_observables(self) -> list[Observable]:
        """Returns the list of all Observables discovered for this Alert."""
        return self.query_engine.all_observables

    @property
    def all_objects(self) -> list[Union[Analysis, Observable]]:
        """Returns the list of all Analysis and Observable objects in the tree."""
        return self.query_engine.all_objects

    def get_analysis_by_type(self, analysis_type: Type[Analysis]) -> list[Analysis]:
        """Returns the list of all Analysis of a given type."""
        return self.query_engine.get_analysis_by_type(analysis_type)

    def get_observables_by_type(self, o_type: str) -> list[Observable]:
        """Returns the list of Observables that match the given type."""
        return self.query_engine.get_observables_by_type(o_type)

    def find_observable(self, criteria: Callable) -> Optional[Observable]:
        """Find a single observable matching the criteria."""
        return self.query_engine.find_observable(criteria)

    def find_observables(self, criteria: Callable) -> list[Observable]:
        """Find all observables matching the criteria."""
        return self.query_engine.find_observables(criteria)

    def get_observable(self, uuid: str) -> Optional[Observable]:
        """Returns the Observable object for the given uuid."""
        return self.query_engine.get_observable(uuid)

    def get_observable_by_spec(self, o_type: str, o_value: str, o_time=None) -> Optional[Observable]:
        """Returns the Observable object by type and value, and optionally time, or None if it cannot be found."""
        return self.query_engine.get_observable_by_spec(o_type, o_value, o_time)

    def search_tree(self, root_object, tags=()) -> list[Union[Analysis, Observable]]:
        """Searches the analysis tree starting from root_object for objects with the given tags."""
        return self.query_engine.search_tree(root_object, tags)

    def search_tree_by_callback(self, root_object, callback) -> list[Union[Analysis, Observable]]:
        """Searches the analysis tree starting from root_object using a callback function."""
        return self.query_engine.search_tree_by_callback(root_object, callback)

    def iterate_all_references(self, target: Union[Analysis, Observable]) -> Iterable[Union[Analysis, Observable]]:
        """Iterates through all objects that refer to target."""
        return self.query_engine.iterate_all_references(target)

    # ------------------

    def _raise_for_size_limit(self, source: Union[Analysis, Observable], source_size: int):
        pass

        # not doing a size limit anymore

        # XXX: refactor: there should be common interface for getting the size of an object
        #size_limit = get_config_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_ANALYSIS_DISK_SIZE)
        #if size_limit:
            #if self.root_analysis.total_size + source_size > size_limit:
                #raise ExcessiveFileDataSizeError(f"size limit of {size_limit} exceeded for {source} in {self.root_analysis}")

    # TODO: deal with too many observables here
    def add_observable(self, analysis: Analysis, observable: Observable) -> Observable:
        """Adds the Observable to this Analysis.  Returns the Observable object, or the one that already existed."""
        assert isinstance(analysis, Analysis)
        assert isinstance(observable, Observable)

        # check if the observable already exists in the analysis
        existing_observable = analysis.get_existing_observable(observable)
        if existing_observable:
            logging.debug(f"observable {observable} already exists in analysis {analysis}, returning existing observable")
            return existing_observable

        # inject managers into observable
        observable.inject_analysis_tree_manager(self)
        observable.inject_file_manager(self.file_manager)

        # check the size limit before recording the observable
        self._raise_for_size_limit(observable, sys.getsizeof(observable.json))

        # record the observable
        # we may get back an existing observable if it already exists in the registry
        observable = self.observable_registry.record(observable)

        # modify the analysis tree
        analysis.add_observable_to_tree(observable)

        # notify the event bus
        self.event_bus.fire_event(analysis, EVENT_OBSERVABLE_ADDED, observable)

        return observable

    def add_analysis(self, observable: Observable, analysis: Analysis) -> Analysis:
        """Adds the Analysis to this Observable.  Returns the Analysis object."""
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)

        # inject managers into analysis
        analysis.inject_analysis_tree_manager(self)
        analysis.inject_file_manager(self.file_manager)

        self._raise_for_size_limit(analysis, sys.getsizeof(analysis.details))

        # reference what observable this analysis is for
        analysis.observable = observable

        # does this analysis already exist?
        # XXX: refactor
        # usually this is because you copied and pasted another AnalysisModule and didn't change the generated_analysis_type function
        if analysis.module_path in observable._analysis and observable._analysis[analysis.module_path] is not analysis:
            logging.error(f"replacing analysis {observable._analysis[analysis.module_path]} with {analysis} for {observable} (are you returning the correct type from generated_analysis_type()?)")

        # newly added analysis is always set to modified so it gets saved to JSON file
        analysis.set_details_modified()

        observable.add_analysis_to_tree(analysis, observable)
        logging.debug("added analysis {} key {} to observable {}".format(analysis, analysis.module_path, observable))
        self.event_bus.fire_event(observable, EVENT_ANALYSIS_ADDED, analysis)

        return analysis

    # persistence manager facade
    # ------------------------------------------------------------------------

    def load_analysis_details(self, analysis: Analysis) -> bool:
        return self.persistence_manager.load_analysis_details(analysis)

    def save_analysis_details(self, analysis: Analysis) -> bool:
        return self.persistence_manager.save_analysis_details(analysis)

    def flush_analysis_details(self, analysis: Analysis):
        self.persistence_manager.flush_analysis_details(analysis)

    def reset_analysis_details(self, analysis: Analysis):
        self.persistence_manager.reset_analysis_details(analysis)

    def discard_analysis_details(self, analysis: Analysis):
        self.persistence_manager.discard_analysis_details(analysis)

    def flush_all_analysis(self):
        """Calls flush() on all Analysis objects in the tree."""
        self.persistence_manager.flush_all_analysis()

    def clear_all_analysis(self):
        """Removes all analysis from all observables."""
        for observable in self.query_engine.all_observables:
            observable.clear_analysis()

    def reset_tree(self, retain_original_observables=True):
        """Resets the analysis tree, optionally retaining original observables.

        Args:
            retain_original_observables: If True, keeps observables that came with the original alert
        """
        self.persistence_manager.reset_tree(retain_original_observables)

    def materialize_tree(self):
        """Utility function to replace specific dict() in json with runtime object references."""
        self.persistence_manager.materialize_tree()

    def serialize_observable_registry(self) -> dict:
        return self.persistence_manager.serialize_observable_registry()

    def deserialize_observable_registry(self, json_data: dict):
        self.persistence_manager.deserialize_observable_registry(json_data)

    def serialize_dependency_tracking(self) -> list[dict]:
        return self.persistence_manager.serialize_dependency_tracking()

    def deserialize_dependency_tracking(self, json_data: list[dict]):
        self.persistence_manager.deserialize_dependency_tracking(json_data)

    def load(self):
        """Loads the analysis tree from the JSON data."""
        self.persistence_manager.load()

    # XXX: this is super weird
    def add_no_analysis(self, observable: Observable, analysis: Analysis, instance: Optional[str]=None):
        # does this analysis already exist?
        # usually this is because you copied and pasted another AnalysisModule and didn't change the generated_analysis_type function
        if MODULE_PATH(analysis, instance=instance) in observable._analysis:
            logging.warning("replacing analysis {} with empty analysis - means you returned False from execute_analysis but you still added analysis".format(
                observable._analysis[MODULE_PATH(analysis, instance=instance)]))
            return

        # this is used to remember that analysis was not generated
        observable._analysis[MODULE_PATH(analysis, instance=instance)] = False
        logging.debug("recorded no analysis of type {} instance {} for observable {}".format(analysis, instance, observable))

    def add_observable_by_spec(self, analysis: Analysis, o_type: str, o_value: str, o_time=None, sort_order=100, volatile=False) -> Optional[Observable]:
        """Adds this observable specified by type, value and time to this Analysis.  
           Returns the new Observable object, or the one that already existed."""
        assert isinstance(analysis, Analysis)
        assert isinstance(o_type, str)

        observable = self.observable_registry.record_by_spec(o_type, o_value, o_time=o_time, sort_order=sort_order, volatile=volatile)
        if observable is None:
            return None

        return self.add_observable(analysis, observable)

    def record_observable(self, observable):
        """Records the given observable into the observable_store if it does not already exist.
        Returns the new one if recorded or the existing one if not."""
        from saq.analysis.observable import Observable

        assert isinstance(observable, Observable)

        # Use the registry to record the observable
        recorded_observable = self.observable_registry.record(observable)

        return recorded_observable

    # analytics facade
    # ------------------------------------------------------------------------

    def is_on_detection_path(self, target_object: Union[Analysis, Observable]) -> bool:
        """Returns True if the target object or any node down to (but not including) the root has a detection point."""
        return self.analytics.is_on_detection_path(target_object)

    def get_all_tags(self) -> list[str]:
        """Return all unique tags for the entire analysis tree."""
        return self.analytics.get_all_tags()

    def get_all_detection_points(self) -> list[DetectionPoint]:
        """Returns all DetectionPoint objects found in any DetectableObject in the hierarchy."""
        return self.analytics.get_all_detection_points()

    def has_detections(self) -> bool:
        """Returns True if this analysis tree has at least one DetectionPoint somewhere."""
        return self.analytics.has_detections()

    def calculate_priority(self) -> int:
        """Calculates and returns the priority score for the analysis tree."""
        return self.analytics.calculate_priority()

    def get_tree_statistics(self) -> dict:
        """Returns statistics about the analysis tree."""
        return self.analytics.get_tree_statistics()

    # validator facade
    # ------------------------------------------------------------------------

    def validate_tree_integrity(self) -> List[str]:
        """Validates the integrity of the analysis tree and returns a list of issues found."""
        return self.validator.validate_tree_integrity()