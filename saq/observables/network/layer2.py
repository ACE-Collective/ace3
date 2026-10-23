import re
from typing import Optional

from saq.analysis.observable import Observable
from saq.constants import F_MAC_ADDRESS
from saq.observables.base import ObservableValueError
from saq.observables.generator import register_observable_type


RE_MAC = re.compile(r'^([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?$')


def normalize_mac_address(value: str) -> Optional[str]:
    """Returns the mac address as lowercase aa-bb-cc-dd-ee-ff, or None if it does not parse.

    Producers disagree on the separator (tshark uses ':', Windows and EDR tools '-'), and the same card
    must be the same observable whichever one saw it."""
    m = RE_MAC.match(value.strip())
    if m is None:
        return None
    return '-'.join(m.groups()).lower()


class MacAddressObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MAC_ADDRESS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        normalized = normalize_mac_address(new_value)
        if normalized is None:
            raise ObservableValueError(f"{new_value} does not parse as a mac address")

        self._value = normalized
        self.mac_parts = tuple(normalized.split('-'))

    # lookups (get_observable_by_spec) and exclusions pass the raw value they were given,
    # so it is compared in canonical form, falling back to as-is when it does not parse
    def _compare_value(self, other_value):
        if isinstance(other_value, str):
            other_value = normalize_mac_address(other_value) or other_value
        return self.value == other_value

    def matches(self, value):
        return self._compare_value(value)

    def mac_address(self, sep=':'):
        """Return the mac address formatted with the given separator. Defaults to :"""
        return sep.join(self.mac_parts)

register_observable_type(F_MAC_ADDRESS, MacAddressObservable)