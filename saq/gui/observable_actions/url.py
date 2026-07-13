from saq.constants import ACTION_URL_CRAWL, ACTION_URLSCAN
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionUrlCrawl(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_URL_CRAWL
        self.description = "Download & render screenshot of URL content"
        self.action_path = 'analysis/observable_actions/url_crawl.html'
        self.icon = 'download-alt'
        self.modifies_analysis = True

class ObservableActionUrlscan(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_URLSCAN
        self.description = "Submit to urlscan.io"
        self.action_path = 'analysis/observable_actions/urlscan.html'
        self.icon = 'eye-open'
        self.modifies_analysis = True