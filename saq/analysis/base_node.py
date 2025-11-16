
from uuid import uuid4
from typing import TYPE_CHECKING, Optional

from saq.analysis.detection_point import DetectionPoint
from saq.analysis.event_source import EventSource
from saq.analysis.tag import Tag

if TYPE_CHECKING:
    from saq.analysis.analysis_tree.analysis_tree_manager import AnalysisTreeManager
    from saq.analysis.file_manager.file_manager_interface import FileManagerInterface

KEY_TAGS = 'tags'
KEY_DETECTIONS = 'detections'
KEY_SORT_ORDER = 'sort_order'

class BaseNode():
    """The base class of a node in the analysis tree."""

    def __init__(
        self,
        uuid: Optional[str]=None,
        sort_order: int=100):

        self.uuid:str = uuid or str(uuid4())

        self.tags:list[Tag] = []
        self.detections:list[DetectionPoint] = []
        self.sort_order:int = sort_order

        # composition-based component managers
        self._event_source = EventSource()
        #self._tag_manager = TagManager(tags=self._tags)
        #self._detection_manager = DetectionManager(detections=self._detections)
        #self._sort_manager = SortManager(sort_order)

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

    def add_tag(self, tag: str):
        assert isinstance(tag, str)
        if tag in [t.name for t in self.tags]:
            return

        t = Tag(name=tag)
        self.tags.append(t)
        
    def remove_tag(self, tag: str):
        assert isinstance(tag, str)
        targets = [t for t in self.tags if t.name == tag]
        for target in targets:
            self.tags.remove(target)

    def clear_tags(self):
        self.tags.clear()

    def has_tag(self, tag_value):
        """Returns True if this object has this tag."""
        return tag_value in [x.name for x in self.tags]

    # detection management
    # ------------------------------------------------------------------------

    def has_detection_points(self) -> bool:
        """Returns True if this object has at least one detection point, False otherwise."""
        return len(self.detections) != 0

    def add_detection_point(self, description: str, details=None) -> DetectionPoint:
        """Adds the given detection point to this object."""
        assert isinstance(description, str)
        assert description

        detection = DetectionPoint(description, details)

        if detection in self.detections:
            return detection

        self.detections.append(detection)
        return detection

    def clear_detection_points(self):
        self.detections.clear()

    def get_json_data(self) -> dict:
        return {
            KEY_TAGS: self.tags,
            KEY_DETECTIONS: self.detections,
            KEY_SORT_ORDER: self.sort_order,
        }

    def set_json_data(self, data: dict):
        if KEY_TAGS in data:
            self.tags = data[KEY_TAGS]
        if KEY_DETECTIONS in data:
            self.detections = data[KEY_DETECTIONS]
        if KEY_SORT_ORDER in data:
            self.sort_order = data[KEY_SORT_ORDER]

    # event management
    # ------------------------------------------------------------------------

    def add_event_listener(self, event, callback):
        self._event_source.add_event_listener(event, callback)

    def fire_event(self, event, *args, **kwargs):
        self._event_source.fire_event(self, event, *args, **kwargs)

    def clear_event_listeners(self):
        self._event_source.clear_event_listeners()