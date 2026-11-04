import logging
from saq.analysis.observable import Observable
from saq.constants import F_AV_STREETNAME, F_IDS_STREETNAME, F_SNORT_SIGNATURE


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

class AVStreetnameObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AV_STREETNAME, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class IDSStreetnameObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_IDS_STREETNAME, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
