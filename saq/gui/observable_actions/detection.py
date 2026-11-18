from saq.constants import ACTION_DISABLE_DETECTION, ACTION_ENABLE_DETECTION
from saq.database.util.observable_detection import default_detection_expiration
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionEnableDetection(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_ENABLE_DETECTION
        self.description = "Enable observable for future detection"
        self.action_path = 'analysis/observable_actions/enable_detection.html'
        self.icon = 'ok'

    def default_expiration(self, observable_type):
        return default_detection_expiration(observable_type)

class ObservableActionDisableableDetection(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_DISABLE_DETECTION
        self.description = "Disable observable for future detection"
        self.action_path = 'analysis/observable_actions/disable_detection.html'
        self.icon = 'remove'