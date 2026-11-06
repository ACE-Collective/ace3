from saq.constants import F_ASSET, F_HOSTNAME
from saq.observables.base import CaselessObservable


class HostnameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_HOSTNAME, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()


class AssetObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_ASSET, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
