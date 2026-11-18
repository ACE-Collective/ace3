from saq.analysis.observable import Observable
from saq.constants import F_INDICATOR


class IndicatorObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_INDICATOR, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
