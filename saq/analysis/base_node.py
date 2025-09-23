
from uuid import uuid4
from typing import TYPE_CHECKING, Optional

from saq.analysis.detectable import DetectionManager
from saq.analysis.event_source import EventSource
from saq.analysis.sortable import SortManager
from saq.analysis.taggable import TagManager

if TYPE_CHECKING:
    from saq.analysis.analysis_tree.analysis_tree_manager import AnalysisTreeManager
    from saq.analysis.file_manager.file_manager_interface import FileManagerInterface


class BaseNode():
    """The base class of a node in the analysis tree."""

    def __init__(self, *args, uuid: Optional[str]=None, sort_order: int=100, **kwargs):
        super().__init__(*args, **kwargs)

        self.uuid = uuid or str(uuid4())

        # composition-based component managers
        self._tag_manager = TagManager(event_source=self)
        self._detection_manager = DetectionManager(event_source=self)
        self._sort_manager = SortManager(sort_order)
        self._event_source = EventSource()

        # a reference to the RootAnalysis object this analysis belongs to (injected)
        self._analysis_tree_manager: Optional["AnalysisTreeManager"] = None

        # file I/O manager (injected)
        self._file_manager: Optional["FileManagerInterface"] = None

    @property
    def analysis_tree_manager(self) -> "AnalysisTreeManager":
        if self._analysis_tree_manager is None:
            raise RuntimeError("analysis_tree_manager is not set")

        return self._analysis_tree_manager
    
    @analysis_tree_manager.setter
    def analysis_tree_manager(self, value: "AnalysisTreeManager"):
        from saq.analysis.analysis_tree.analysis_tree_manager import AnalysisTreeManager
        assert isinstance(value, AnalysisTreeManager)
        self._analysis_tree_manager = value

    @property
    def file_manager(self) -> "FileManagerInterface":
        if self._file_manager is None:
            raise RuntimeError("file_manager is not set")

        return self._file_manager

    @file_manager.setter
    def file_manager(self, value: "FileManagerInterface"):
        from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
        assert isinstance(value, FileManagerInterface)
        self._file_manager = value
    

    # injection methods
    # ------------------------------------------------------------------------

    def inject_analysis_tree_manager(self, analysis_tree_manager: "AnalysisTreeManager"):
        from saq.analysis.analysis_tree.analysis_tree_manager import AnalysisTreeManager
        assert isinstance(analysis_tree_manager, AnalysisTreeManager)
        self.analysis_tree_manager = analysis_tree_manager

    def inject_file_manager(self, file_manager: "FileManagerInterface"):
        from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
        assert isinstance(file_manager, FileManagerInterface)
        self.file_manager = file_manager

    # tag management
    # ------------------------------------------------------------------------

    @property
    def tags(self):
        return self._tag_manager.tags

    @tags.setter
    def tags(self, value):
        self._tag_manager.tags = value

    def add_tag(self, tag):
        self._tag_manager.add_tag(tag)

    def remove_tag(self, tag):
        self._tag_manager.remove_tag(tag)

    def clear_tags(self):
        self._tag_manager.clear_tags()

    def has_tag(self, tag_value):
        """Returns True if this object has this tag."""
        return self._tag_manager.has_tag(tag_value)

    # detection management
    # ------------------------------------------------------------------------

    @property
    def detections(self):
        return self._detection_manager.detections

    @detections.setter
    def detections(self, value):
        self._detection_manager.detections = value

    def has_detection_points(self):
        """Returns True if this object has at least one detection point, False otherwise."""
        return self._detection_manager.has_detection_points()

    def add_detection_point(self, description, details=None):
        """Adds the given detection point to this object."""
        self._detection_manager.add_detection_point(description, details)

    def clear_detection_points(self):
        self._detection_manager.clear_detection_points()

    # sort management
    # ------------------------------------------------------------------------

    @property
    def sort_order(self):
        return self._sort_manager.sort_order

    @sort_order.setter
    def sort_order(self, value):
        self._sort_manager.sort_order = value

    # event management
    # ------------------------------------------------------------------------

    def add_event_listener(self, event, callback):
        self._event_source.add_event_listener(event, callback)

    def fire_event(self, event, *args, **kwargs):
        self._event_source.fire_event(event, *args, **kwargs)

    def clear_event_listeners(self):
        self._event_source.clear_event_listeners()