from saq.constants import ACTION_COLLECT_FILE, ACTION_FILE_DOWNLOAD_AS_ZIP, ACTION_FILE_RENDER, ACTION_FILE_VIEW_AS_HEX, ACTION_FILE_VIEW_AS_TEXT
from saq.gui.observable_actions.base import ObservableAction


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

class ObservableActionCollectFile(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_COLLECT_FILE
        self.description = "Collect File"
        self.action_path = 'analysis/observable_actions/collect_file.html'
        self.icon = 'save-file'
        self.modifies_analysis = True

class ObservableActionFileRender(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_RENDER
        self.description = "Attempt to render screenshot of HTML"
        self.action_path = 'analysis/observable_actions/file_render.html'
        self.icon = 'camera'
        self.modifies_analysis = True