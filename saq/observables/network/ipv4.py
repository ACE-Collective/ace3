import ipaddress

import iptools
from saq.analysis.observable import Observable
from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.constants import F_IPV4, F_IPV4_CONVERSATION, F_IPV4_FULL_CONVERSATION, parse_ipv4_conversation, parse_ipv4_full_conversation
from saq.environment import get_global_runtime_settings
from saq.observables.base import ObservableValueError
from saq.observables.generator import register_observable_type


class IPv4Observable(Observable):

    def __init__(self, *args, **kwargs):
        super().__init__(F_IPV4, *args, **kwargs)

    @property
    def jinja_template_path(self):
        return "analysis/ipv4_observable.html"

    @Observable.value.setter
    def value(self, new_value):
        # type check the value
        try:
            ipaddress.IPv4Address(new_value)
        except Exception:
            raise ObservableValueError(f"{new_value} is not a valid ipv4 address")

        self._value = new_value.strip()
    
    @property
    def jinja_available_actions(self):
        result = []
        if not self.is_managed():
            result = [ ]
            result.extend(super().jinja_available_actions)

        return result

    def is_managed(self):
        """Returns True if this IP address is listed as part of a managed network, False otherwise."""
        # see [network_configuration]
        # these are initialized in the global initialization function
        for cidr in get_global_runtime_settings().managed_networks:
            try:
                if self.value in cidr:
                    return True
            except:
                return False

        return False

    def matches(self, value):
        # is this CIDR notation?
        if '/' in value:
            try:
                return self.value in iptools.IpRange(value)
            except:
                pass

        # otherwise it has to match exactly
        return self.value == value


class IPv4ObservablePresenter(ObservablePresenter):
    """Presenter for IPv4Observable."""

    @property
    def template_path(self) -> str:
        return "analysis/ipv4_observable.html"


register_observable_presenter(IPv4Observable, IPv4ObservablePresenter)


class IPv4ConversationObservable(Observable):
    def __init__(self, *args, **kwargs):
        self._source = None
        self._dest = None
        super().__init__(F_IPV4_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        parsed_ipv4_conversation = parse_ipv4_conversation(self.value)
        if len(parsed_ipv4_conversation) == 2:
            self._source, self._dest = parsed_ipv4_conversation
        else:
            raise ObservableValueError(f"invalid IPv4 Convo: {new_value}")
        
    @property
    def source(self):
        return self._source

    @property
    def destination(self):
        return self._dest

class IPv4FullConversationObservable(Observable):
    
    def __init__(self, *args, **kwargs):
        self._source = None
        self._source_port = None
        self._dest = None 
        self._dest_port = None
        super().__init__(F_IPV4_FULL_CONVERSATION, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()
        parsed_ipv4_full_conversation = parse_ipv4_full_conversation(self.value)
        if len(parsed_ipv4_full_conversation) == 4:
            self._source, self._source_port, self._dest, self._dest_port = parsed_ipv4_full_conversation
        else:
            raise ObservableValueError(f"invalid IPv4 Full Convo: {new_value}")

    @property
    def source(self):
        return self._source

    @property
    def source_port(self):
        return self._source_port

    @property
    def dest(self):
        return self._dest

    @property   
    def dest_port(self):
        return self._dest_port

register_observable_type(F_IPV4, IPv4Observable)
register_observable_type(F_IPV4_CONVERSATION, IPv4ConversationObservable)
register_observable_type(F_IPV4_FULL_CONVERSATION, IPv4FullConversationObservable)