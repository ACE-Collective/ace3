from urllib.parse import urlsplit

from saq.analysis.observable import Observable
from saq.analysis.presenter.observable_presenter import register_observable_action
from saq.configuration.config import get_config
from saq.constants import F_URI_PATH, F_URL, F_USER_AGENT
from saq.gui import (
    ObservableActionSeparator,
    ObservableActionUrlCrawl,
    ObservableActionUrlscan,
    ObservableActionCheckForClickers,
    ObservableActionOpenSplunkClickerSearch,
)
from saq.observables.base import ObservableValueError
from saq.observables.generator import register_observable_type

from saq.util import is_subdomain

# URLs with these schemes always name a host; mailto:, file:, data: and scheme-less values are not checked
HOST_URL_SCHEMES = frozenset({"http", "https", "ftp"})


class UserAgentObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_USER_AGENT, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()



class URIPathObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_URI_PATH, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    def is_managed(self) -> bool:
        for parent in self.parents:
            if parent.observable and parent.observable.is_managed():
                return True

        return False


class URLObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_URL, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        # Modules add URLs from attacker-written content (office relationships, kit pages, protected-URL
        # parameters) and not all of them check what they add, so "https:.." would otherwise reach the
        # crawler, urlscan and the domain lookups.
        try:
            parts = urlsplit(new_value)
            missing_host = parts.scheme in HOST_URL_SCHEMES and not (parts.hostname or "").strip(".")
        except ValueError:
            # urlsplit refuses some netlocs that still name a host ("http://[x/", NFKC look-alikes); an
            # attacker wrote them, so keep the URL rather than drop it
            missing_host = False

        if missing_host:
            raise ObservableValueError(f"{new_value} has no host")

        self._value = new_value

    @property
    def jinja_available_actions(self):
        result = [
            ObservableActionUrlscan(),
            ObservableActionUrlCrawl(),
            ObservableActionSeparator(),
        ]
        result.extend(super().jinja_available_actions)
        return result

    def is_managed(self):
        """Returns True if this URL has a managed domain."""
        # imported here: every process that loads the observable types imports this module, and urlfinderlib
        # costs ~11 MB where nothing else needs it (the hunter)
        from urlfinderlib.url import URL

        url = URL(self.value)
        for fqdn in get_config().global_settings.local_domains:
            if is_subdomain(url.netloc_idna, fqdn):
                return True

        for fqdn in get_config().global_settings.local_email_domains:
            if is_subdomain(url.netloc_idna, fqdn):
                return True

        return False

register_observable_type(F_USER_AGENT, UserAgentObservable)
register_observable_type(F_URI_PATH, URIPathObservable)
register_observable_type(F_URL, URLObservable)

# crawl the URL with phishkit
register_observable_action(F_URL, ObservableActionUrlCrawl)
# "Check for clickers" (generic) and "Open clicker search in Splunk" (source-specific)
register_observable_action(F_URL, ObservableActionCheckForClickers)
register_observable_action(F_URL, ObservableActionOpenSplunkClickerSearch)