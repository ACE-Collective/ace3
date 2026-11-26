"""service_alert_automation: sweeps every enabled alert automation rule each interval_seconds, on
the primary node only (docs/ALERT_AUTOMATION.md, *The service*). It is not a queue service: the
runs table's unique key and the claim on a pending run, not a row lock, keep a rule from acting
twice on an alert."""

import logging
import threading
from typing import Optional, Type

from pydantic import Field

from saq.alert_automation.rules import Rule, load_rules, sweep_rule
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_ALERT_AUTOMATION
from saq.database.pool import remove_all_sessions
from saq.database.util.node import is_primary_node
from saq.error.reporting import log_loop_exception
from saq.service import ACEServiceInterface
from saq.shutdown import is_shutting_down


class AlertAutomationServiceConfig(ServiceConfig):
    interval_seconds: int = Field(default=60, gt=0, description="how long the service waits between sweeps of the rules")
    batch_size: int = Field(default=100, gt=0, description="how many alerts a sweep reads at a time")
    max_action_attempts: int = Field(default=5, gt=0, description="how many times a failing action is tried before it is marked failed")


class AlertAutomationService(ACEServiceInterface):

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return AlertAutomationServiceConfig

    def __init__(self):
        self.shutdown = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.rules: list[Rule] = []

    def _stopping(self) -> bool:
        return self.shutdown.is_set() or is_shutting_down()

    def sweep(self) -> None:
        """Sweeps each rule once. A rule that fails is logged and the others still run."""
        config = get_service_config(SERVICE_ALERT_AUTOMATION)
        for rule in self.rules:
            if self._stopping():
                return

            try:
                sweep_rule(rule, config.batch_size, config.max_action_attempts, self._stopping)
            except Exception as e:
                log_loop_exception(e, f"alert automation rule {rule.name} sweep failed", extra={"rule": rule.name})
            finally:
                remove_all_sessions()

    def loop(self) -> None:
        interval = get_service_config(SERVICE_ALERT_AUTOMATION).interval_seconds
        while not self._stopping():
            self.sweep()
            self.shutdown.wait(interval)

    def _start_on_primary(self) -> bool:
        if not is_primary_node():
            # the rules act on the cluster's alerts; one node sweeps them
            logging.info("alert automation runs on the primary node only; this service stays idle")
            return False

        self.rules = load_rules()
        return True

    def start(self):
        if not self._start_on_primary():
            return

        self.thread = threading.Thread(target=self.loop, name="alert-automation", daemon=True)
        self.thread.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return True

    def start_single_threaded(self):
        """Sweeps each rule once and returns; wait() returns too."""
        try:
            if self._start_on_primary():
                self.sweep()
        finally:
            self.shutdown.set()

    def stop(self):
        self.shutdown.set()

    def wait(self):
        # the service runs until it is stopped, idle or not: `ace service start` reads a wait()
        # that returns as the service having finished
        while not self.shutdown.wait(timeout=1):
            pass

        if self.thread is not None:
            # the sweep checks for the stop between alerts; one action can still be running
            self.thread.join(timeout=get_service_config(SERVICE_ALERT_AUTOMATION).shutdown_deadline_seconds)
            if self.thread.is_alive():
                logging.warning("the alert automation sweep did not stop within the shutdown deadline")
