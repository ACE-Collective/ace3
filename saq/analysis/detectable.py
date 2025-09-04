import logging
from saq.analysis.detection_point import DetectionPoint
from saq.constants import EVENT_DETECTION_ADDED


class DetectionManager:
    """Manages detection-related functionality for any object through composition."""

    KEY_DETECTIONS = 'detections'

    def __init__(self, event_source=None):
        self._detections = []
        self._event_source = event_source

    @property
    def detections(self) -> list[DetectionPoint]:
        return self._detections

    @detections.setter
    def detections(self, value: DetectionPoint):
        assert isinstance(value, list)
        assert all([isinstance(x, DetectionPoint) for x in value]) or all([isinstance(x, dict) for x in value])
        self._detections = value

    def has_detection_points(self) -> bool:
        """Returns True if this object has at least one detection point, False otherwise."""
        return len(self._detections) != 0

    def add_detection_point(self, description: str, details=None):
        """Adds the given detection point to this object."""
        assert isinstance(description, str)
        assert description

        detection = DetectionPoint(description, details)

        if detection in self._detections:
            return

        self._detections.append(detection)
        logging.debug("added detection point {} to {}".format(detection, self._event_source or self))
        
        # Fire event if we have an event source
        if self._event_source and hasattr(self._event_source, 'fire_event'):
            self._event_source.fire_event(self._event_source, EVENT_DETECTION_ADDED, detection)

    def clear_detection_points(self):
        self._detections.clear()

    def get_json_data(self) -> dict:
        """Returns detection data for JSON serialization."""
        return {DetectionManager.KEY_DETECTIONS: self._detections}

    def set_json_data(self, value):
        """Sets detection data from JSON deserialization."""
        if DetectionManager.KEY_DETECTIONS in value:
            self._detections = value[DetectionManager.KEY_DETECTIONS]
