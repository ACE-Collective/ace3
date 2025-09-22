import inspect
import logging
from typing import Optional

from saq.analysis.dependency import AnalysisDependency
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable_registry import ObservableRegistry


class AnalysisDependencyManager:
    """Manages analysis dependencies for a root analysis context."""

    def __init__(self, observable_registry: ObservableRegistry):
        """Initialize the dependency manager.
        
        Args:
            observable_registry: The observable registry to use for resolving observable IDs
        """
        self.dependency_tracking: list[AnalysisDependency] = []
        self.observable_registry = observable_registry

    def add_dependency(self, source_observable, source_analysis, source_analysis_instance: Optional[str], 
                      target_observable, target_analysis, target_analysis_instance: Optional[str]) -> AnalysisDependency:
        """Add a new analysis dependency.
        
        Args:
            source_observable: The observable being analyzed when the request was made
            source_analysis: The analysis class that made the request
            source_analysis_instance: Optional instance name for the source analysis
            target_observable: The observable that needs to be analyzed
            target_analysis: The analysis class that needs to be executed
            target_analysis_instance: Optional instance name for the target analysis
            
        Returns:
            The AnalysisDependency object (new or existing)
            
        Raises:
            RuntimeError: If adding the dependency would create a circular dependency
        """
        from saq.analysis.analysis import Analysis
        from saq.analysis.observable import Observable
        
        assert isinstance(source_observable, Observable)
        assert inspect.isclass(source_analysis) and issubclass(source_analysis, Analysis)
        assert source_analysis_instance is None or isinstance(source_analysis_instance, str)
        assert isinstance(target_observable, Observable)
        assert inspect.isclass(target_analysis) and issubclass(target_analysis, Analysis)
        assert target_analysis_instance is None or isinstance(target_analysis_instance, str)

        # Check if this dependency already exists
        for dep in self.dependency_tracking:
            if (dep.source_observable_id == source_observable.uuid and 
                dep.source_analysis_type == MODULE_PATH(source_analysis, instance=source_analysis_instance) and
                dep.target_observable_id == target_observable.uuid and
                dep.target_analysis_type == MODULE_PATH(target_analysis, instance=target_analysis_instance)):
                logging.debug("already added dependency for {} {} ({}) --> {} {} ({})".format(
                              source_observable, source_analysis, source_analysis_instance,
                              target_observable, target_analysis, target_analysis_instance))
                return dep

        # Check for circular dependencies
        self._check_circular_dependency(source_observable, source_analysis, source_analysis_instance,
                                       target_observable, target_analysis, target_analysis_instance)

        # Create new dependency
        dep = AnalysisDependency(
            target_observable.uuid, 
            MODULE_PATH(target_analysis, instance=target_analysis_instance), 
            source_observable.uuid, 
            MODULE_PATH(source_analysis, instance=source_analysis_instance),
            self.observable_registry)

        logging.debug("tracking {}".format(dep))
        self.dependency_tracking.append(dep)
        self._link_dependencies(dep)
        
        return dep

    def remove_dependency(self, dep: AnalysisDependency) -> None:
        """Remove a dependency from tracking.
        
        Args:
            dep: The dependency to remove
        """
        try:
            logging.debug("removing {}".format(dep))
            self.dependency_tracking.remove(dep)
        except ValueError:
            logging.error("requested removal of untracked dependency {}".format(dep))

    def get_dependencies_for_observable(self, observable_id: str) -> list[AnalysisDependency]:
        """Get all dependencies targeting a specific observable.
        
        Args:
            observable_id: The ID of the observable to get dependencies for
            
        Returns:
            List of dependencies targeting the observable
        """
        return [dep for dep in self.dependency_tracking if dep.target_observable_id == observable_id]

    def get_dependency_by_type(self, observable_id: str, analysis_type: str) -> Optional[AnalysisDependency]:
        """Get a specific dependency by observable ID and analysis type.
        
        Args:
            observable_id: The ID of the observable
            analysis_type: The analysis type string
            
        Returns:
            The matching dependency or None if not found
        """
        for dep in self.get_dependencies_for_observable(observable_id):
            if dep.target_analysis_type == analysis_type:
                return dep
        return None

    @property
    def active_dependencies(self) -> list[AnalysisDependency]:
        """Get dependencies that are not failed, delayed, or resolved.
        
        Returns:
            List of active dependencies sorted by execution order
        """
        _buffer = []
        for dep in self.dependency_tracking:
            if dep.failed:
                continue
            if dep.delayed:
                continue
            if dep.resolved:
                continue
            _buffer.append(dep)

        # Sort by score (number of dependencies in chain)
        return sorted(_buffer, key=lambda dep: dep.score, reverse=False)

    @property
    def all_dependencies(self) -> list[AnalysisDependency]:
        """Get all tracked dependencies.
        
        Returns:
            List of all dependencies
        """
        return self.dependency_tracking

    def _check_circular_dependency(self, source_observable, source_analysis, source_analysis_instance: Optional[str],
                                  target_observable, target_analysis, target_analysis_instance: Optional[str]) -> None:
        """Check if adding a dependency would create a circular dependency.
        
        Raises:
            RuntimeError: If adding the dependency would create a circular dependency
        """
        def resolve_node(so, sa, to, ta):
            nonlocal target_analysis, target_analysis_instance

            dependencies = self.get_dependencies_for_observable(so.uuid)
            for dep in [dep for dep in dependencies if dep.target_analysis_type == sa]:
                if MODULE_PATH(target_analysis, instance=target_analysis_instance) == dep.source_analysis_type:
                    raise RuntimeError("CIRCULAR DEPENDENCY ERROR: {} {} {} {} -> {}".format(so, sa, to, ta, dep))

                # Recurse to parent nodes
                source_obs = self.observable_registry.get_by_id(dep.source_observable_id)
                target_obs = self.observable_registry.get_by_id(dep.target_observable_id)
                resolve_node(source_obs, dep.source_analysis_type, target_obs, dep.target_analysis_type)

        resolve_node(source_observable, 
                    MODULE_PATH(source_analysis, instance=source_analysis_instance), 
                    target_observable, 
                    MODULE_PATH(target_analysis, instance=target_analysis_instance))

    def _link_dependencies(self, target_dep: AnalysisDependency) -> None:
        """Link dependencies by setting .next and .prev properties.
        
        Args:
            target_dep: The dependency to link with existing dependencies
        """
        for source_dep in self.dependency_tracking:
            if source_dep is target_dep:
                continue

            if (source_dep.target_observable_id == target_dep.source_observable_id and 
                source_dep.target_analysis_type == target_dep.source_analysis_type):
                source_dep.next = target_dep
                target_dep.prev = source_dep

    def serialize(self) -> list[dict]:
        """Serialize dependencies to JSON format.
        
        Returns:
            List of dependency dictionaries
        """
        return [dep.json for dep in self.dependency_tracking]

    def deserialize(self, dependencies_data: list[dict]) -> None:
        """Deserialize dependencies from a dict loaded from JSON format.
        
        Args:
            observable_registry: The observable registry to use for resolving observable IDs
            dependencies_data: List of dependency dictionaries
        """
        self.dependency_tracking = []
        for dep_dict in dependencies_data:
            dep = AnalysisDependency.from_json(dep_dict, self.observable_registry)
            self.dependency_tracking.append(dep)
            
        # Re-link all dependencies
        for dep in self.dependency_tracking:
            self._link_dependencies(dep) 