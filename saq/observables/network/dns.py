import validators
from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_action, register_observable_presenter
from saq.configuration.config import get_config
from saq.constants import F_FQDN
from saq.gui import ObservableActionCheckForClickers, ObservableActionOpenSplunkClickerSearch
from saq.observables.base import CaselessObservable, ObservableValueError
from saq.observables.generator import register_observable_type
from saq.util import is_subdomain

class FQDNObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FQDN, *args, **kwargs)

    @property
    def jinja_template_path(self):
        return "analysis/fqdn_observable.html"

    @CaselessObservable.value.setter
    def value(self, new_value):
        # For whatever reason, the validators library returns an exception instead of raising it.
        if not bool(validators.domain(new_value)):
            raise ObservableValueError(f"{new_value} is not a valid fqdn")

        self._value = new_value.strip()

    @property
    def jinja_available_actions(self):
        result = []
        if not self.is_managed():
            result = [ ]
            result.extend(super().jinja_available_actions)

        return result

    def is_managed(self):
        """Returns True if this FQDN is a managed DN."""
        for fqdn in get_config().global_settings.local_domains:
            if is_subdomain(self.value, fqdn):
                return True

        for fqdn in get_config().global_settings.local_email_domains:
            if is_subdomain(self.value, fqdn):
                return True

        return False


class FQDNObservablePresenter(ObservablePresenter):
    """Presenter for FQDNObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/fqdn_observable.html"


register_observable_presenter(FQDNObservable, FQDNObservablePresenter)

register_observable_type(F_FQDN, FQDNObservable)

# "Check for clickers" (generic) and "Open clicker search in Splunk" (source-specific)
register_observable_action(F_FQDN, ObservableActionCheckForClickers)
register_observable_action(F_FQDN, ObservableActionOpenSplunkClickerSearch)