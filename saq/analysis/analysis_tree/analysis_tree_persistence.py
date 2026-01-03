from typing import TYPE_CHECKING

from saq.analysis.analysis import Analysis
from saq.analysis.dependency_manager import AnalysisDependencyManager
from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
from saq.analysis.observable_registry import ObservableRegistry
from saq.analysis.persistence_manager import AnalysisDetailsPersistenceManager
from saq.analysis.serialize.observable_registry_serializer import ObservableRegistrySerializer
from saq.analysis.detection_point import DetectionPoint
from saq.constants import F_FILE

if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis
    from saq.analysis.analysis_tree.analysis_tree_query import AnalysisTreeQueryEngine


class AnalysisTreePersistenceManager:
    """Manager for the persistence and serialization of the analysis tree.
    
    This class handles:
    - Analysis details persistence (save, load, flush, reset, discard)
    - Observable registry serialization/deserialization
    - Dependency tracking serialization/deserialization
    - Tree materialization and hydration
    - Tree loading from JSON data
    """

    def __init__(
        self, 
        file_manager: FileManagerInterface,
        root_analysis: "RootAnalysis",
        observable_registry: ObservableRegistry,
        dependency_manager: AnalysisDependencyManager,
        query_engine: "AnalysisTreeQueryEngine"
    ):
        """Initialize the AnalysisTreePersistenceManager.

        Args:
            file_manager: The FileManagerInterface for file operations
            root_analysis: The RootAnalysis instance
            observable_registry: The ObservableRegistry instance
            dependency_manager: The AnalysisDependencyManager instance
            query_engine: The AnalysisTreeQueryEngine for querying the tree
        """
        self.file_manager = file_manager
        self.root_analysis = root_analysis
        self.observable_registry = observable_registry
        self.dependency_manager = dependency_manager
        self.query_engine = query_engine
        
        # Internal persistence manager for analysis details
        self._details_persistence_manager = AnalysisDetailsPersistenceManager(file_manager)

    # Analysis Details Persistence Methods
    # ------------------------------------------------------------------------

    def load_analysis_details(self, analysis: Analysis) -> bool:
        """Loads the details of the specified analysis from disk.
        
        Args:
            analysis: The Analysis object to load details for
            
        Returns:
            bool: True if details were successfully loaded, False otherwise
        """
        return self._details_persistence_manager.load_details(analysis)

    def save_analysis_details(self, analysis: Analysis) -> bool:
        """Saves the details of the specified analysis to disk.
        
        Args:
            analysis: The Analysis object to save details for
            
        Returns:
            bool: True if details were successfully saved, False otherwise
        """
        return self._details_persistence_manager.save(analysis)

    def flush_analysis_details(self, analysis: Analysis):
        """Calls save() and then clears the details property of the analysis.
        
        Args:
            analysis: The Analysis object to flush
        """
        self._details_persistence_manager.flush(analysis)

    def reset_analysis_details(self, analysis: Analysis):
        """Deletes the current analysis output if it exists.
        
        Args:
            analysis: The Analysis object to reset
        """
        self._details_persistence_manager.reset(analysis)

    def discard_analysis_details(self, analysis: Analysis):
        """Simply discards the details of this analysis, not saving any changes.
        
        Args:
            analysis: The Analysis object to discard details for
        """
        self._details_persistence_manager.discard_details(analysis)

    # Tree-level Operations
    # ------------------------------------------------------------------------

    def flush_all_analysis(self):
        """Calls flush() on all Analysis objects in the tree."""
        for analysis in self.query_engine.all_analysis:
            if analysis is not self.root_analysis:
                self.flush_analysis_details(analysis)

    def reset_tree(self, retain_original_observables=True):
        """Resets the analysis tree, optionally retaining original observables.

        Args:
            retain_original_observables: If True, keeps observables that came with the original alert
        """
        # Clear external details storage for all analysis (except root)
        for analysis in self.query_engine.all_analysis:
            if analysis is not self.root_analysis:
                self.reset_analysis_details(analysis)

        # Remove analysis objects from all observables
        for observable in self.query_engine.all_observables:
            observable.clear_analysis()

        if retain_original_observables:
            # Remove observables that didn't come with the original alert
            original_uuids = set([o.id for o in self.root_analysis.observables])
            remove_list = []
            for uuid in list(self.observable_registry.store.keys()):
                if uuid not in original_uuids:
                    remove_list.append(uuid)

            for uuid in remove_list:
                # If the observable is a F_FILE then try to also delete the file
                if self.observable_registry.store[uuid].type == F_FILE:
                    observable = self.observable_registry.store[uuid]
                    if hasattr(observable, "exists") and getattr(observable, "exists", False):
                        file_path = getattr(observable, "full_path", None)
                        if file_path and self.root_analysis.file_manager:
                            self.root_analysis.file_manager.delete_file(file_path)

                self.observable_registry.remove(uuid)

        # Remove tags from observables
        for observable in self.query_engine.all_observables:
            observable.clear_tags()

    # Serialization Methods
    # ------------------------------------------------------------------------

    def serialize_observable_registry(self) -> dict:
        """Serializes the observable registry to a dictionary.
        
        Returns:
            dict: Serialized observable registry data
        """
        return ObservableRegistrySerializer.serialize(self.observable_registry)

    def deserialize_observable_registry(self, json_data: dict, inject_managers=True):
        """Deserializes observable registry data from a dictionary.
        
        Args:
            json_data: Dictionary containing serialized observable registry data
            inject_managers: If True, injects managers into observables after deserialization
        """
        ObservableRegistrySerializer.deserialize(self.observable_registry, json_data)

        if inject_managers:
            # inject managers into observables
            for observable in self.observable_registry.store.values():
                observable.analysis_tree_manager = self.root_analysis.analysis_tree_manager
                observable.file_manager = self.file_manager

    def serialize_dependency_tracking(self) -> list[dict]:
        """Serializes the dependency tracking to a list of dictionaries.
        
        Returns:
            list[dict]: Serialized dependency tracking data
        """
        return self.dependency_manager.serialize()

    def deserialize_dependency_tracking(self, json_data: list[dict]):
        """Deserializes dependency tracking data from a list of dictionaries.
        
        Args:
            json_data: List of dictionaries containing serialized dependency tracking data
        """
        self.dependency_manager.deserialize(json_data)

    # Tree Materialization and Loading
    # ------------------------------------------------------------------------

    def materialize_tree(self):
        """Utility function to replace specific dict() in json with runtime object references.
        
        This method converts serialized JSON data back into proper object references,
        tags, detection points, and relationships.
        """
        # Load the Analysis objects in the Observables
        for observable in self.observable_registry.store.values():
            observable._load_analysis()

        # Load the Observable references in the Analysis objects
        for analysis in self.query_engine.all_analysis:
            analysis._load_observable_references()

        # Load DetectionPoints
        for analysis in self.query_engine.all_analysis:
            analysis.detections = [
                DetectionPoint.from_json(dp) for dp in analysis.detections
            ]

        for observable in self.query_engine.all_observables:
            observable.detections = [
                DetectionPoint.from_json(dp) for dp in observable.detections
            ]

        # Load Relationships
        for observable in self.query_engine.all_observables:
            observable._load_relationships()

    def load(self):
        """Loads the analysis tree from the JSON data.
        
        This method performs the complete loading process:
        1. Load Analysis objects in Observables
        2. Inject managers into analysis objects
        3. Load Observable references in Analysis objects
        4. Load DetectionPoints for analysis and observables
        5. Load Relationships for observables
        """
        # load the Analysis objects in the Observables
        for observable in self.observable_registry.store.values():
            observable._load_analysis()

        # load the Observable references in the Analysis objects
        for analysis in self.query_engine.all_non_root_analysis:
            # inject managers into analysis
            analysis.analysis_tree_manager = self.root_analysis.analysis_tree_manager
            analysis.file_manager = self.file_manager

        for analysis in self.query_engine.all_analysis:
            # load all observable references
            analysis._load_observable_references()

        # load DetectionPoints
        for analysis in self.query_engine.all_analysis:
            analysis.detections = [DetectionPoint.from_json(dp) for dp in analysis.detections]

        for observable in self.query_engine.all_observables:
            observable.detections = [DetectionPoint.from_json(dp) for dp in observable.detections]

        # load Relationships
        for observable in self.query_engine.all_observables:
            observable._load_relationships()

        # dependency tracking is now handled by the dependency manager during deserialization

    # Archive Operations
    # ------------------------------------------------------------------------

    def archive_analysis_details(self):
        """Archives analysis details by clearing external details storage for all non-root analysis.
        
        This is typically used when archiving alerts to save space while retaining
        observables and tags.
        """
        # Clear external details storage for all analysis (except root)
        for analysis in self.query_engine.all_non_root_analysis:
            self.reset_analysis_details(analysis)

        # Clean up any files associated with observables that weren't part of the original alert
        retained_files = set()
        for observable in self.query_engine.all_observables:
            # Skip the ones that came with the alert
            if observable in self.root_analysis.observables:
                continue

            if observable.type == F_FILE:
                file_path = getattr(observable, 'full_path', None)
                if file_path:
                    retained_files.add(file_path)

        self.file_manager.archive_files(retained_files)