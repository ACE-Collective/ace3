import importlib
import logging
from typing import Type

from pydantic import BaseModel, Field

from saq.configuration.config import get_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_MONITORING
from saq.error.reporting import report_exception
from saq.monitoring.threaded_monitor import ACEThreadedMonitor
from saq.service import ACEServiceInterface

class ThreadedMonitorConfig(BaseModel):
    python_module: str = Field(description="the Python module of the threaded monitor")
    python_class: str = Field(description="the Python class of the threaded monitor")
    name: str = Field(description="the unique name of the threaded monitor")
    frequency: float = Field(description="how often (in seconds) the monitor should emit data", default=1)
    enabled: bool = Field(description="whether the monitor is enabled", default=True)

class ACEMonitoringServiceConfig(ServiceConfig):
    monitors: list[ThreadedMonitorConfig] = Field(description="the list of threaded monitors")

class ACEMonitoringService(ACEServiceInterface):

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ACEMonitoringServiceConfig

    def __init__(self):
        self.config: ACEMonitoringServiceConfig = get_config().get_service_config(SERVICE_MONITORING)
        self.load_threaded_monitors()

    def load_threaded_monitors(self):
        self.threaded_monitors: list[ACEThreadedMonitor] = []
        for monitor_config in self.config.monitors:
            if not monitor_config.enabled:
                logging.info("threaded monitor %s is disabled, skipping", monitor_config.name)
                continue
            try:
                module = importlib.import_module(monitor_config.python_module)
                class_definition = getattr(module, monitor_config.python_class)
                monitor = class_definition(name=monitor_config.name, frequency=monitor_config.frequency)
                existing_index = next(
                    (i for i, m in enumerate(self.threaded_monitors) if m.name == monitor_config.name),
                    None,
                )
                if existing_index is not None:
                    logging.info(
                        "replacing threaded monitor %s with new configuration from %s.%s",
                        monitor_config.name, monitor_config.python_module, monitor_config.python_class,
                    )
                    self.threaded_monitors[existing_index] = monitor
                else:
                    logging.info(
                        "loaded threaded monitor %s from %s.%s",
                        monitor_config.name, monitor_config.python_module, monitor_config.python_class,
                    )
                    self.threaded_monitors.append(monitor)
            except Exception as e:
                logging.error("error loading threaded monitor %s: %s", monitor_config.name, e)
                report_exception(e)

    def start(self):
        for monitor in self.threaded_monitors:
            monitor.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        for monitor in self.threaded_monitors:
            if not monitor.wait_for_start(timeout):
                return False

        return True

    def start_single_threaded(self):
        for monitor in self.threaded_monitors:
            monitor.start_single_threaded()

    def stop(self):
        for monitor in self.threaded_monitors:
            monitor.stop()

    def wait(self):
        for monitor in self.threaded_monitors:
            monitor.wait()