from typing import TYPE_CHECKING, Callable
from saq.constants import VALID_EVENTS

if TYPE_CHECKING:
    from saq.analysis import Analysis, Observable


class EventSource:
    """Supports callbacks for events by keyword."""

    def __init__(self):
        self.clear_event_listeners()

    def clear_event_listeners(self):
        self.event_listeners = {} # key = string, value = [] of callback functions

    def add_event_listener(self, event: str, callback: Callable):
        assert isinstance(event, str)
        assert callback

        if event not in self.event_listeners:
            self.event_listeners[event] = []

        if callback not in self.event_listeners[event]:
            self.event_listeners[event].append(callback)

    def fire_event(self, source: "Analysis | Observable", event: str, *args, **kwargs):
        from saq.analysis import Analysis, Observable
        assert isinstance(source, Analysis) or isinstance(source, Observable)
        assert event in VALID_EVENTS

        if event in self.event_listeners:
            for callback in self.event_listeners[event]:
                callback(source, event, *args, **kwargs)