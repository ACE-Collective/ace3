
from uuid import uuid4
from typing import Optional

from saq.analysis.detectable import DetectionManager
from saq.analysis.event_source import EventSource
from saq.analysis.sortable import SortManager
from saq.analysis.taggable import TagManager


class BaseNode(EventSource):
    """The base class of a node in the analysis tree."""

    def __init__(self, *args, uuid: Optional[str]=None, sort_order: int=100, **kwargs):
        super().__init__(*args, **kwargs)

        self.uuid = uuid or str(uuid4())

        # composition-based component managers
        self._tag_manager = TagManager(event_source=self)
        self._detection_manager = DetectionManager(event_source=self)
        self._sort_manager = SortManager(sort_order)

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
