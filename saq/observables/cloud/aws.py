from saq.analysis.observable import Observable
from saq.constants import F_AWS_ACCESS_KEY_ID, F_AWS_ACCOUNT_ID, F_AWS_INSTANCE_ID, F_AWS_PRINCIPAL_ID, F_AWS_PRIVATE_DNS_NAME, F_AWS_SECURITY_GROUP_ID, F_AWS_USERNAME
from saq.observables.base import ObservableValueError


class AWSAccessKeyIdObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AWS_ACCESS_KEY_ID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class AWSPrincipalIdObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AWS_PRINCIPAL_ID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class AWSAccountObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AWS_ACCOUNT_ID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        # AWS Account IDs are always strings comprised of 12 digits
        if len(self._value) != 12 or not self._value.isdigit():
            raise ObservableValueError(f"{new_value} is not a valid AWS account ID")


class AWSUsername(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AWS_USERNAME, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()


class AWSInstanceID(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AWS_INSTANCE_ID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()


class AWSSecurityGroupID(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AWS_SECURITY_GROUP_ID, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()


class AWSPrivateDNSName(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_AWS_PRIVATE_DNS_NAME, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
