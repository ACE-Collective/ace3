from saq.analysis.observable import Observable
from saq.constants import F_YARA_RULE, F_YARA_STRING
from saq.observables.base import ObservableValueError


class YaraRuleObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_YARA_RULE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class YaraStringObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_YARA_STRING, *args, **kwargs)

        try:
            parsed = self._value.rsplit(":", 1)
            self._rule = parsed[0]
            self._string = parsed[1]
        except Exception as e:
            raise ObservableValueError(f"expected format for yara string is rule:$string error: {e}")

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def rule(self):
        return self._rule

    @property
    def string(self):
        return self._string

    @property
    def string(self):
        if not self._value:
            return None

        parsed = self._value.rsplit(":", 1)
        if len(parsed) != 2:
            return None

        return parsed[1]
