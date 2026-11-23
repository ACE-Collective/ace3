from abc import abstractmethod
import logging
import threading
from typing import Optional

from saq.error.reporting import log_loop_exception

# how long wait() gives a stopped monitor to finish the execute() it is in
STOP_TIMEOUT_SECONDS = 5

# how often wait() checks for stop() while the monitor runs
WAIT_POLL_SECONDS = 1


class ACEThreadedMonitor:
    def __init__(self, name: str, frequency: float):
        self.started_event = threading.Event()
        self.shutdown_event = threading.Event()
        self.main_thread: Optional[threading.Thread] = None
        self.name = name
        self.frequency = frequency
        self.stop_timeout = STOP_TIMEOUT_SECONDS

    def main_loop(self):
        self.started_event.set()
        while not self.shutdown_event.is_set():
            try:
                self.execute()
            except Exception as e:
                log_loop_exception(e, f"error in {self.name} monitor")

            self.shutdown_event.wait(self.frequency)

    @abstractmethod
    def execute(self):
        ... # pragma: no cover

    def start(self):
        self.main_thread = threading.Thread(target=self.main_loop, name=self.name)
        self.main_thread.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.started_event.wait(timeout)

    def start_single_threaded(self):
        self.execute()

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        if self.main_thread is None:
            return

        # `ace service start` reads a wait() that returns as the service having finished, so
        # this runs until stop(), which `ace service start` always calls when it shuts down,
        # or until the thread dies on its own
        while not self.shutdown_event.is_set() and self.main_thread.is_alive():
            self.main_thread.join(WAIT_POLL_SECONDS)

        self.main_thread.join(self.stop_timeout)
        if self.main_thread.is_alive():
            logging.warning("monitor %s did not stop within %s seconds", self.name, self.stop_timeout,
                            extra={"monitor": self.name})
