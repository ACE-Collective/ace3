from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import sys
from threading import RLock
from typing import Any, Optional, TYPE_CHECKING

from fluent import sender

if TYPE_CHECKING:
    from saq.configuration.schema import MonitorDefinitionConfig

from saq.configuration.config import get_config

@dataclass
class Monitor:
    category: str
    name: str
    data_type: type
    description: str

@dataclass
class CacheEntry:
    identifier: str
    value: Any
    time: datetime

def _format_message(monitor: Monitor, value: Any, identifier: Optional[str]=None) -> str:
    identifier_message = ""
    if identifier is not None:
        identifier_message = f" <{identifier}> "

    return "MONITOR [{}] ({}){}: {}".format(monitor.category, monitor.name, identifier_message, value)

class MonitorEmitter:
    def __init__(self):
        self.use_logging = False
        self.use_stdout = False
        self.use_stderr = False
        self.use_cache = False
        self.use_fluent_bit = False
        self.fluent_bit_sender = None

        # monitor definitions
        self.definitions: dict[str, "MonitorDefinitionConfig"] = {}
        self._suppression_lock = RLock()
        self._last_emission_times: dict[str, datetime] = {}

        # in-memory cache
        self.cache = {}
        self.cache_lock = RLock()

    def set_definitions(self, definitions: dict[str, "MonitorDefinitionConfig"]):
        self.definitions = definitions

    def emit_cache(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        with self.cache_lock:
            if monitor.category not in self.cache:
                self.cache[monitor.category] = {}

            self.cache[monitor.category][monitor.name] = CacheEntry(identifier, value, datetime.now())

    def emit_logging(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        logging.debug(_format_message(monitor, value, identifier))
        return True

    def emit_stdout(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        print(_format_message(monitor, value, identifier))
        return True

    def emit_stderr(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        sys.stderr.write(_format_message(monitor, value, identifier))
        sys.stderr.write("\n")
        return True

    def emit_fluent_bit(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "category": monitor.category,
                "name": monitor.name,
                "value": value,
            }
            if identifier is not None:
                data["identifier"] = identifier
            self.fluent_bit_sender.emit(None, data)
            return True
        except Exception as e:
            logging.error("failed to emit monitor data to fluent-bit: %s", e)
            return False

    def close(self):
        if self.fluent_bit_sender is not None:
            self.fluent_bit_sender.close()

    def emit(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        assert isinstance(value, monitor.data_type)

        # check monitor definitions for enabled/suppression gating
        definition = self.definitions.get(monitor.name)
        if definition is not None:
            if not definition.enabled:
                return False

            if definition.suppression_duration is not None:
                with self._suppression_lock:
                    last_time = self._last_emission_times.get(monitor.name)
                    if last_time is not None and (datetime.now() - last_time) < timedelta(seconds=definition.suppression_duration):
                        return False
                    self._last_emission_times[monitor.name] = datetime.now()

        if self.use_cache:
            self.emit_cache(monitor, value, identifier)

        if self.use_logging:
            self.emit_logging(monitor, value, identifier)

        if self.use_stdout:
            self.emit_stdout(monitor, value, identifier)

        if self.use_stderr:
            self.emit_stderr(monitor, value, identifier)

        if self.use_fluent_bit:
            self.emit_fluent_bit(monitor, value, identifier)

        return True

    def dump_cache(self, fp):
        with self.cache_lock:
            for category in sorted(self.cache.keys()):
                for name in sorted(self.cache[category].keys()):
                    cache_entry = self.cache[category][name]
                    identifier_str = ""
                    if cache_entry.identifier:
                        identifier_str = f":{cache_entry.identifier}"

                    fp.write(f"[{category}] ({name}{identifier_str}): {cache_entry.value} @ {cache_entry.time}\n")

global_emitter = MonitorEmitter()

def get_emitter() -> MonitorEmitter:
    return global_emitter

def reset_emitter():
    global global_emitter
    global_emitter.close()
    global_emitter = MonitorEmitter()

def emit_monitor(monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
    assert isinstance(value, monitor.data_type)
    return get_emitter().emit(monitor, value, identifier)

def enable_monitor_logging():
    get_emitter().use_logging = True

def enable_monitor_stdout():
    get_emitter().use_stdout = True

def enable_monitor_stderr():
    get_emitter().use_stderr = True

def enable_monitor_cache():
    get_emitter().use_cache = True

def set_monitor_definitions(definitions: dict[str, "MonitorDefinitionConfig"]):
    get_emitter().set_definitions(definitions)

def enable_monitor_fluent_bit(hostname, port, tag):
    emitter = get_emitter()
    emitter.fluent_bit_sender = sender.FluentSender(tag, host=hostname, port=port)
    emitter.use_fluent_bit = True

def initialize_monitoring():
    reset_emitter()

    if get_config().monitor.use_stdout:
        enable_monitor_stdout()

    if get_config().monitor.use_stderr:
        enable_monitor_stderr()

    if get_config().monitor.use_logging:
        enable_monitor_logging()

    if get_config().monitor.use_cache:
        enable_monitor_cache()

    if get_config().monitor.fluent_bit is not None:
        enable_monitor_fluent_bit(
            hostname=get_config().monitor.fluent_bit.hostname,
            port=get_config().monitor.fluent_bit.port,
            tag=get_config().monitor.fluent_bit.tag,
        )

    if get_config().monitor.definitions:
        set_monitor_definitions(get_config().monitor.definitions)
