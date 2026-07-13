from saq.constants import ACTION_CHECK_FOR_CLICKERS, ACTION_OPEN_CLICKER_SEARCH_SPLUNK
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionCheckForClickers(ObservableAction):
    """Generic, source-agnostic action: tag the observable with the clicker_detection
    directive so every configured clicker module (Splunk, etc.) runs against it."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_CHECK_FOR_CLICKERS
        self.description = "Check for clickers"
        self.action_path = 'analysis/observable_actions/check_for_clickers.html'
        self.icon = 'search'
        self.modifies_analysis = True


class ObservableActionOpenSplunkClickerSearch(ObservableAction):
    """Source-specific action: open the clicker search in Splunk so the analyst can
    investigate the logs directly, without needing to run detection first."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_OPEN_CLICKER_SEARCH_SPLUNK
        self.description = "Open clicker search in Splunk"
        self.action_path = 'analysis/observable_actions/open_clicker_search_splunk.html'
        self.icon = 'box-arrow-up-right'
