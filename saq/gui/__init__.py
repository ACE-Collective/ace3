from saq.lazy_exports import lazy_getattr

# saq.gui imports nothing itself: the observable types and the integrations import their observable actions
# from here in every process, and this init loaded saq.gui.alert with them (Flask, the database models).
# saq.gui.alert registers the RootAnalysis presenter when it is imported, which the GUI views and the alerts
# API do. These names stay importable from saq.gui, each loaded the first time it is asked for (PEP 562).
_EXPORTS = {
    "GUIAlert": "saq.gui.alert",
    "ObservableActionSeparator": "saq.gui.observable_actions.base",
    "ObservableAction": "saq.gui.observable_actions.base",
    "ObservableActionSetSIPIndicatorStatus_Analyzed": "saq.gui.observable_actions.sip",
    "ObservableActionSetSIPIndicatorStatus_Informational": "saq.gui.observable_actions.sip",
    "ObservableActionSetSIPIndicatorStatus_New": "saq.gui.observable_actions.sip",
    "ObservableActionDownloadFileAsZip": "saq.gui.observable_actions.file",
    "ObservableActionViewAsHex": "saq.gui.observable_actions.file",
    "ObservableActionViewAsText": "saq.gui.observable_actions.file",
    "ObservableActionCollectFile": "saq.gui.observable_actions.file",
    "ObservableActionFileRender": "saq.gui.observable_actions.file",
    "ObservableActionUploadToVt": "saq.gui.observable_actions.vt",
    "ObservableActionViewInVt": "saq.gui.observable_actions.vt",
    "ObservableActionDisableableDetection": "saq.gui.observable_actions.detection",
    "ObservableActionEnableDetection": "saq.gui.observable_actions.detection",
    "ObservableActionMarkInteresting": "saq.gui.observable_actions.interesting",
    "ObservableActionUnmarkInteresting": "saq.gui.observable_actions.interesting",
    "ObservableActionUrlCrawl": "saq.gui.observable_actions.url",
    "ObservableActionUrlscan": "saq.gui.observable_actions.url",
    "ObservableActionCheckForClickers": "saq.gui.observable_actions.clicker",
    "ObservableActionOpenSplunkClickerSearch": "saq.gui.observable_actions.clicker",
    "ObservableActionAddComment": "saq.gui.observable_actions.comment",
    "ObservableActionAddLocalEmailDomain": "saq.gui.observable_actions.management",
    "ObservableActionAddTag": "saq.gui.observable_actions.management",
    "ObservableActionAdjustExpiration": "saq.gui.observable_actions.management",
    "node_translate_gui": "saq.gui.translation",
    "translate_alert_redirect": "saq.gui.translation",
}

__getattr__ = lazy_getattr(__name__, _EXPORTS)
