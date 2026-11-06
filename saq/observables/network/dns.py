import validators
from saq.configuration.config import get_config
from saq.constants import F_FQDN
from saq.observables.base import CaselessObservable, ObservableValueError
from saq.util import is_subdomain

class FQDNObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FQDN, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        # For whatever reason, the validators library returns an exception instead of raising it.
        if not bool(validators.domain(new_value)):
            raise ObservableValueError(f"{new_value} is not a valid fqdn")

        self._value = new_value.strip()

    def is_managed(self):
        """Returns True if this FQDN is a managed DN."""
        for fqdn in get_config().global_settings.local_domains:
            if is_subdomain(self.value, fqdn):
                return True

        for fqdn in get_config().global_settings.local_email_domains:
            if is_subdomain(self.value, fqdn):
                return True

        return False
