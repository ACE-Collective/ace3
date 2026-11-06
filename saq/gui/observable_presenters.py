"""The core observable types' presenters and actions.

The GUI imports this module where it renders observables (app/analysis/views/index.py). The
observable types used to register these themselves, which loaded the GUI's action classes into every
process that read an alert.
"""

from saq.analysis.presenter.observable_presenter import (
    ObservablePresenter,
    register_observable_action,
    register_observable_presenter,
)
from saq.constants import F_FQDN, F_URL
from saq.gui.observable_actions.base import ObservableActionSeparator
from saq.gui.observable_actions.clicker import ObservableActionCheckForClickers, ObservableActionOpenSplunkClickerSearch
from saq.gui.observable_actions.file import (
    ObservableActionCollectFile,
    ObservableActionDownloadFileAsZip,
    ObservableActionFileRender,
    ObservableActionViewAsHex,
    ObservableActionViewAsText,
)
from saq.gui.observable_actions.url import ObservableActionUrlCrawl
from saq.observables.asset import HostnameObservable
from saq.observables.email import EmailConversationObservable
from saq.observables.file import FileLocationObservable, FileObservable, SHA256Observable
from saq.observables.intel import IndicatorObservable
from saq.observables.network.dns import FQDNObservable
from saq.observables.network.ip import IPObservable
from saq.observables.network.ipv4 import IPv4Observable
from saq.observables.user import UserObservable


class _TemplatePresenter(ObservablePresenter):
    """A presenter that differs from the default only in its template."""

    TEMPLATE_PATH: str

    @property
    def template_path(self) -> str:
        return self.TEMPLATE_PATH


class UserObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/user_observable.html"


class EmailConversationObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/email_conversation_observable.html"


class HostnameObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/hostname_observable.html"


class IndicatorObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/indicator_observable.html"


class FQDNObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/fqdn_observable.html"


class IPObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/ip_observable.html"


class IPv4ObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/ipv4_observable.html"


class SHA256ObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/sha256_observable.html"


class FileObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/file_observable.html"

    def _build_available_actions(self) -> list:
        result = [
            ObservableActionDownloadFileAsZip(),
            ObservableActionViewAsHex(),
            ObservableActionViewAsText(),
            ObservableActionFileRender(),
            ObservableActionSeparator(),
        ]
        result.extend(super()._build_available_actions())
        return result


class FileLocationObservablePresenter(_TemplatePresenter):
    TEMPLATE_PATH = "analysis/file_location_observable.html"

    def _build_available_actions(self) -> list:
        result = [ObservableActionCollectFile(), ObservableActionSeparator()]
        result.extend(super()._build_available_actions())
        return result


register_observable_presenter(UserObservable, UserObservablePresenter)
register_observable_presenter(EmailConversationObservable, EmailConversationObservablePresenter)
register_observable_presenter(HostnameObservable, HostnameObservablePresenter)
register_observable_presenter(IndicatorObservable, IndicatorObservablePresenter)
register_observable_presenter(FQDNObservable, FQDNObservablePresenter)
register_observable_presenter(IPObservable, IPObservablePresenter)
register_observable_presenter(IPv4Observable, IPv4ObservablePresenter)
register_observable_presenter(SHA256Observable, SHA256ObservablePresenter)
register_observable_presenter(FileObservable, FileObservablePresenter)
register_observable_presenter(FileLocationObservable, FileLocationObservablePresenter)

# crawl the URL with phishkit
register_observable_action(F_URL, ObservableActionUrlCrawl)
# "Check for clickers" (generic) and "Open clicker search in Splunk" (source-specific)
for _observable_type in (F_URL, F_FQDN):
    register_observable_action(_observable_type, ObservableActionCheckForClickers)
    register_observable_action(_observable_type, ObservableActionOpenSplunkClickerSearch)
