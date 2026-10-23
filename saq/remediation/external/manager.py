"""Wires the external-remediation-check collector daemon to per-probe workers.

Reads ``external_remediation_probe_*`` blocks from the config (loaded via
:class:`ExternalRemediationProbeConfig`), instantiates each probe, and
registers a worker per probe with the collector. Mirrors
:class:`saq.file_collection.manager.FileCollectionManager`.
"""
import logging

from saq.configuration import get_config
from saq.remediation.external.collector import ExternalRemediationCheckCollector
from saq.remediation.external.probe import load_probe_from_config
from saq.remediation.external.worker import ExternalRemediationCheckWorker


class ExternalRemediationCheckManager:

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
    ):
        self.workers: dict[str, ExternalRemediationCheckWorker] = {}
        self.collector = ExternalRemediationCheckCollector(
            lock_timeout_seconds=lock_timeout_seconds,
            initial_retry_delay_seconds=initial_retry_delay_seconds,
            max_retry_delay_seconds=max_retry_delay_seconds,
        )

    def load_workers(self):
        for probe_config in get_config().external_remediation_probes:
            if not probe_config.enabled:
                logging.info(f"external remediation probe {probe_config.name} disabled")
                continue
            probe = load_probe_from_config(probe_config)
            self.add_worker(ExternalRemediationCheckWorker(probe))

    def add_worker(self, worker: ExternalRemediationCheckWorker):
        if worker.probe.name in self.workers:
            raise ValueError(f"probe worker {worker.probe.name} already exists")
        logging.info(f"loaded external remediation probe worker {worker.probe.name}")
        self.workers[worker.probe.name] = worker
        self.collector.register_listener(worker.probe.name, worker)

    def start(self):
        self.load_workers()
        self.collector.start()
        for worker in self.workers.values():
            worker.start()

    def start_single_threaded(self):
        # one pass: collect what is due, then work through all of it in this thread
        self.load_workers()
        self.collector.start_single_threaded()
        for worker in self.workers.values():
            worker.start_single_threaded()

    def wait_for_start(self, timeout: float) -> bool:
        for worker in self.workers.values():
            if not worker.wait_for_start(timeout):
                logging.error(f"probe worker {worker.probe.name} did not start")
                return False
        if not self.collector.wait_for_start(timeout):
            logging.error("external remediation check collector did not start")
            return False
        return True

    def stop(self):
        for worker in self.workers.values():
            worker.stop()
        self.collector.stop()

    def wait(self):
        for worker in self.workers.values():
            worker.wait()
        self.collector.wait()
