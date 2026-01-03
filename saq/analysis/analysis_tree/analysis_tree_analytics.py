from typing import TYPE_CHECKING, Union

from saq.analysis.analysis import Analysis
from saq.analysis.analysis_tree.analysis_tree_query import AnalysisTreeQueryEngine
from saq.analysis.observable import Observable
from saq.analysis.search import search_down
from saq.analysis.detection_point import DetectionPoint

if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis


class AnalysisTreeAnalytics:
    """Handles business logic, calculations, and statistics gathering for analysis trees."""

    def __init__(self, root_analysis: "RootAnalysis", query_engine: AnalysisTreeQueryEngine):
        """Initialize the AnalysisTreeAnalytics.

        Args:
            root_analysis: The RootAnalysis instance
            query_engine: The AnalysisTreeQueryEngine for querying the tree
        """
        self.root_analysis = root_analysis
        self.query_engine = query_engine

    def is_on_detection_path(self, target_object: Union[Analysis, Observable]) -> bool:
        """Returns True if the target object or any node down to (but not including) the root has a detection point."""
        if target_object.has_detection_points():
            return True

        return (
            search_down(
                target_object,
                lambda obj: (
                    False if obj is self.root_analysis else obj.has_detection_points()
                ),
            )
            is not None
        )

    def get_all_tags(self) -> list[str]:
        """Return all unique tags for the entire analysis tree."""
        result = []

        for analysis in self.query_engine.all_analysis:
            if analysis.tags is not None:
                result.extend(analysis.tags)

        for observable in self.query_engine.all_observables:
            if observable.tags is not None:
                result.extend(observable.tags)

        return list(set(result))

    def get_all_detection_points(self) -> list[DetectionPoint]:
        """Returns all DetectionPoint objects found in any DetectableObject in the hierarchy."""
        result = []
        for a in self.query_engine.all_analysis:
            result.extend(a.detections)
        for o in self.query_engine.all_observables:
            result.extend(o.detections)

        return result

    def has_detections(self) -> bool:
        """Returns True if this analysis tree has at least one DetectionPoint somewhere."""
        if self.root_analysis.has_detection_points():
            return True
        for a in self.query_engine.all_analysis:
            if a.has_detection_points():
                return True
        for o in self.query_engine.all_observables:
            if o.has_detection_points():
                return True
        return False

    def calculate_priority(self) -> int:
        """Calculates and returns the priority score for the analysis tree."""
        from saq.util.ui import get_tag_score
        score = 0
        for tag in self.get_all_tags():
            score += get_tag_score(tag)
        return score

    def get_tree_statistics(self) -> dict:
        """Returns statistics about the analysis tree."""
        from saq.constants import F_FILE

        stats = {
            "total_analysis": len(self.query_engine.all_analysis),
            "total_observables": len(self.query_engine.all_observables),
            "total_tags": len(self.get_all_tags()),
            "total_detection_points": len(self.get_all_detection_points()),
            "has_detections": self.has_detections(),
            "priority_score": self.calculate_priority(),
            "observable_types": {},
            "analysis_types": {},
            "file_count": 0,
            "delayed_analysis_count": 0,
        }

        # Count observables by type
        for observable in self.query_engine.all_observables:
            o_type = observable.type
            stats["observable_types"][o_type] = (
                stats["observable_types"].get(o_type, 0) + 1
            )
            if o_type == F_FILE:
                stats["file_count"] += 1

        # Count analysis by type
        for analysis in self.query_engine.all_analysis:
            a_type = type(analysis).__name__
            stats["analysis_types"][a_type] = stats["analysis_types"].get(a_type, 0) + 1
            if analysis.delayed:
                stats["delayed_analysis_count"] += 1

        return stats