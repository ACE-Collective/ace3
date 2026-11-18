from saq.analysis.observable import Observable
from saq.constants import F_STRING_EPS, F_STRING_HTML, F_STRING_JAVA, F_STRING_JS, F_STRING_OFFICE, F_STRING_PDF, F_STRING_PE, F_STRING_RTF, F_STRING_SWF, F_STRING_UNIX_SHELL, F_STRING_VBS, F_STRING_WINDOWS_SHELL


class StringEPSObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_EPS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringHTMLObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_HTML, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringJavaObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_JAVA, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringJSObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_JS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringOfficeObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_OFFICE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringPDFObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_PDF, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringPEObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_PE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringRTFObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_RTF, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringSWFObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_SWF, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringUnixShellObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_UNIX_SHELL, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringVBSObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_VBS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value


class StringWindowsShellObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_STRING_WINDOWS_SHELL, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value
