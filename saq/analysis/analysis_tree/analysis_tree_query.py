import inspect
import logging
from typing import TYPE_CHECKING, Callable, Iterable, List, Optional, Type, Union

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.observable_registry import ObservableRegistry

if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis


class AnalysisTreeQueryEngine:
    """Engine for querying the analysis tree."""

    def __init__(self, root_analysis: "RootAnalysis", observable_registry: ObservableRegistry):
        """Initialize the AnalysisTreeQueryEngine.

        Args:
            root_analysis: The RootAnalysis instance
            observable_registry: The ObservableRegistry instance
        """
        self.root_analysis = root_analysis
        self.observable_registry = observable_registry

    def get_observable_by_id(self, uuid: str) -> Optional[Observable]:
        """Returns the Observable object for the given uuid."""
        return self.observable_registry.get_by_id(uuid)

    @property
    def all_analysis(self) -> list[Analysis]:
        """Returns the list of all Analysis performed for this Alert."""

        result = []
        result.append(self.root_analysis)
        for observable in self.observable_registry.store.values():
            for analysis in observable.analysis.values():
                if analysis and isinstance(analysis, Analysis):
                    result.append(analysis)

        return result

    @property
    def all_non_root_analysis(self) -> list[Analysis]:
        """Returns the list of all Analysis performed for this Alert."""

        result = []
        for observable in self.observable_registry.store.values():
            for analysis in observable.analysis.values():
                if analysis and isinstance(analysis, Analysis):
                    result.append(analysis)

        return result

    @property
    def all_observables(self) -> List:
        """Returns the list of all Observables discovered for this Alert."""
        return self.observable_registry.get_all()

    @property
    def all_objects(self) -> list[Union[Analysis, Observable]]:
        """Returns the list of all Observables and Analysis for this RootAnalysis."""
        result: list[Union[Analysis, Observable]] = [_ for _ in self.all_analysis]
        result.extend(self.all_observables)
        return result

    def get_analysis_by_type(self, analysis_type: Type[Analysis]) -> list[Analysis]:
        """Returns the list of all Analysis of a given type."""
        assert inspect.isclass(analysis_type) and issubclass(analysis_type, Analysis)
        return [a for a in self.all_analysis if isinstance(a, analysis_type)]

    def get_observables_by_type(self, o_type: str) -> list[Observable]:
        """Returns the list of Observables that match the given type."""
        return self.observable_registry.get_by_type(o_type)

    def find_observable(self, criteria: Callable):
        """Find a single observable matching the criteria."""
        return self.observable_registry.find(criteria)

    def find_observables(self, criteria: Callable) -> list[Observable]:
        """Find all observables matching the criteria."""
        return self.observable_registry.find_all(criteria)

    def get_observable(self, uuid: str):
        """Returns the Observable object for the given uuid."""
        return self.observable_registry.get_by_id(uuid)

    def get_observable_by_spec(self, o_type: str, o_value: str, o_time=None):
        """Returns the Observable object by type and value, and optionally time, or None if it cannot be found."""
        return self.observable_registry.get_by_spec(o_type, o_value, o_time)

    def iterate_all_references(self, target: Union[Analysis, Observable]) -> Iterable[Union[Analysis, Observable]]:
        """Iterates through all objects that refer to target."""
        if isinstance(target, Observable):
            for analysis in self.all_analysis:
                if target in analysis.observables:
                    yield analysis
        elif isinstance(target, Analysis):
            for observable in self.all_observables:
                if target in observable.all_analysis:
                    yield observable
        else:
            raise ValueError(
                "invalid type {} passed to iterate_all_references".format(type(target))
            )