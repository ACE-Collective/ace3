from saq.constants import ACTION_COLLECT_FILE, ACTION_FILE_DOWNLOAD, ACTION_FILE_DOWNLOAD_AS_ZIP, ACTION_FILE_RENDER, ACTION_FILE_VIEW_AS_HEX, ACTION_FILE_VIEW_AS_HTML, ACTION_FILE_VIEW_AS_TEXT, ACTION_FILE_VIEW_IN_BROWSER
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionDownloadFile(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_DOWNLOAD
        self.description = "Download File"
        self.action_path = 'analysis/observable_actions/download_file.html'
        self.icon = 'download-alt'

class ObservableActionDownloadFileAsZip(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_DOWNLOAD_AS_ZIP
        self.description = "Download File As ZIP"
        self.action_path = 'analysis/observable_actions/download_file_as_zip.html'
        self.icon = 'download-alt'

class ObservableActionViewAsHex(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_AS_HEX
        self.description = "View As Hex"
        self.action_path = 'analysis/observable_actions/view_as_hex.html'
        self.icon = 'zoom-in'

class ObservableActionViewAsText(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_AS_TEXT
        self.description = "View As Text"
        self.action_path = 'analysis/observable_actions/view_as_text.html'
        self.icon = 'file'

class ObservableActionViewAsHtml(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_AS_HTML
        self.description = "Open"
        self.action_path = 'analysis/observable_actions/view_as_html.html'
        self.icon = 'new-window'

class ObservableActionViewInBrowser(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_IN_BROWSER
        self.description = "Open"
        self.action_path = 'analysis/observable_actions/view_in_browser.html'
        self.icon = 'new-window'

class ObservableActionCollectFile(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_COLLECT_FILE
        self.description = "Collect File"
        self.action_path = 'analysis/observable_actions/collect_file.html'
        self.icon = 'save-file'

class ObservableActionFileRender(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_RENDER
        self.description = "Attempt to render screenshot of HTML"
        self.action_path = 'analysis/observable_actions/file_render.html'
        self.icon = 'camera'