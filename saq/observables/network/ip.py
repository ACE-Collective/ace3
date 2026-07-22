from ipaddress import ip_address, ip_network

from saq.analysis.observable import Observable
from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.constants import F_IP, F_IP_CONVERSATION, F_IP_FULL_CONVERSATION, parse_ip_full_conversation, parse_ipv4_conversation
from saq.environment import get_global_runtime_settings
from saq.observables.base import ObservableValueError
from saq.observables.generator import register_observable_type


class IPObservable(Observable):
    # subclasses representing a more specific kind of IP (see EmailFirstHopIPObservable)
    # override this to reuse the validation and managed-network logic under their own type
    OBSERVABLE_TYPE = F_IP

    def __init__(self, *args, **kwargs):
        super().__init__(self.OBSERVABLE_TYPE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        try:
            self._value = new_value.strip()
            self._ip_address = ip_address(self._value)
        except Exception:
            raise ObservableValueError(f"{new_value} is not a valid ip address")

    def is_managed(self) -> bool:
        """Returns True if this IP address is listed as part of a managed network, False otherwise."""
        # see [network_configuration]
        # these are initialized in the global initialization function
        for cidr in get_global_runtime_settings().managed_networks:
            try:
                if str(self._ip_address) in cidr:
                    return True
            except Exception:
                return False

        return False

    def matches(self, value) -> bool:
        # is this CIDR notation?
        if '/' in value:
            try:
                return self._ip_address in ip_network(value)
            except Exception:
                pass

        # otherwise it has to match exactly
        return self.value == value

class IPObservablePresenter(ObservablePresenter):
    """Presenter for IPObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/ip_observable.html"

class IPConversationObservable(Observable):
    def __init__(self, *args, **kwargs):
        self._source = None
        self._dest = None
        self._source_ip = None
        self._dest_ip = None
        super().__init__(F_IP_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        parsed_ip_conversation = parse_ipv4_conversation(self.value)
        if len(parsed_ip_conversation) == 2 and all(parsed_ip_conversation):
            self._source, self._dest = parsed_ip_conversation
            try:
                self._source_ip = ip_address(self._source)
                self._dest_ip = ip_address(self._dest)
            except Exception:
                raise ObservableValueError(f"invalid IP conversation value: {new_value}")
        else:
            raise ObservableValueError(f"invalid IP conversation value: {new_value}")
        
    @property
    def source(self) -> str:
        return self._source

    @property
    def destination(self) -> str:
        return self._dest

class IPFullConversationObservable(Observable):
    
    def __init__(self, *args, **kwargs):
        self._source = None
        self._source_port = None
        self._dest = None 
        self._dest_port = None
        super().__init__(F_IP_FULL_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        parsed_ip_full_conversation = parse_ip_full_conversation(self.value)
        if len(parsed_ip_full_conversation) == 4 and all(parsed_ip_full_conversation):
            self._source, self._source_port, self._dest, self._dest_port = parsed_ip_full_conversation
            try:
                self._source_ip = ip_address(self._source)  
                self._dest_ip = ip_address(self._dest)
            except Exception:
                raise ObservableValueError(f"invalid IP full conversation value: {new_value}")
            
            try:
                self._source_port = int(self._source_port)
                self._dest_port = int(self._dest_port)
            except Exception:
                raise ObservableValueError(f"invalid IP full conversation value: {new_value}")
        else:
            raise ObservableValueError(f"invalid IP full conversation value: {new_value}")

    @property
    def source(self) -> str:
        return self._source

    @property
    def source_port(self):
        return self._source_port

    @property
    def dest(self) -> str:
        return self._dest

    @property   
    def dest_port(self):
        return self._dest_port


register_observable_type(F_IP, IPObservable)
register_observable_type(F_IP_CONVERSATION, IPConversationObservable)
register_observable_type(F_IP_FULL_CONVERSATION, IPFullConversationObservable)

register_observable_presenter(IPObservable, IPObservablePresenter)
