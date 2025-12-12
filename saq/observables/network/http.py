import logging
import re
import urllib
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.constants import F_URI_PATH, F_URL, F_USER_AGENT
from saq.gui import ObservableActionSeparator, ObservableActionUrlCrawl, ObservableActionUrlscan
from saq.observables.generator import register_observable_type
from urlfinderlib.url import URL
from urlfinderlib import find_urls

from saq.util import is_subdomain
from saq.util.url import PROTECTED_URLS, sanitize_protected_url


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
        self._value = sanitize_protected_url(new_value.strip())

    @property
    def jinja_available_actions(self):
        result = [
            ObservableActionUrlscan(),
            ObservableActionUrlCrawl(),
            ObservableActionSeparator(),
        ]
        result.extend(super().jinja_available_actions)
        return result

    @property
    def remediation_targets(self):
        return []

    def is_managed(self):
        """Returns True if this URL has a managed domain."""

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