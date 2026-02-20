
from abc import abstractmethod
import logging
import threading

from saq.error.reporting import report_exception


class ACEThreadedMonitor:
    def __init__(self, name: str, frequency: float):
        self.started_event = threading.Event()
        self.shutdown_event = threading.Event()
        self.monitor_thread = None
        self.name = name
        self.frequency = frequency

    def main_loop(self):
        while not self.shutdown_event.is_set():
            try:
                self.execute()
            except Exception as e:
                logging.error(f"error in {self.name} monitor: {e}")
                report_exception(e)

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
        self.main_thread.join()