from saq.analysis.observable import Observable
from saq.constants import F_MUTEX, F_WINDOWS_REGISTRY, F_WINDOWS_SERVICE


class MutexObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MUTEX, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class WindowsRegistryObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_WINDOWS_REGISTRY, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()


class WindowsServiceObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_WINDOWS_SERVICE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
