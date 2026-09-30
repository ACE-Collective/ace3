import logging
from saq.analysis.observable import Observable
from saq.constants import F_SNORT_SIGNATURE
from saq.observables.generator import register_observable_type


class SnortSignatureObservable(Observable):
    def __init__(self, *args, **kwargs):
        self.signature_id = None
        self.rev = None
        super().__init__(F_SNORT_SIGNATURE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        _ = self.value.split(':')
        if len(_) == 3:
            _, self.signature_id, self.rev = _
        else:
            logging.warning(f"unexpected snort/suricata signature format: {self.value}")

register_observable_type(F_SNORT_SIGNATURE, SnortSignatureObservable)
