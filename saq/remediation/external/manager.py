"""Wires the external-remediation-check collector daemon to per-probe workers.

Reads ``external_remediation_probe_*`` blocks from the config (loaded via
:class:`ExternalRemediationProbeConfig`), instantiates each enabled probe, and
registers a worker per probe with the collector.
"""
import logging
from typing import Iterator

from saq.configuration import get_config
from saq.queue_service import QueueManager
from saq.remediation.external.collector import ExternalRemediationCheckCollector
from saq.remediation.external.probe import load_probe_from_config
from saq.remediation.external.worker import ExternalRemediationCheckWorker


class ExternalRemediationCheckManager(QueueManager[ExternalRemediationCheckWorker]):

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
    ):
        super().__init__(ExternalRemediationCheckCollector(
            lock_timeout_seconds=lock_timeout_seconds,
            initial_retry_delay_seconds=initial_retry_delay_seconds,
            max_retry_delay_seconds=max_retry_delay_seconds,
        ))

    def create_workers(self) -> Iterator[ExternalRemediationCheckWorker]:
        for probe_config in get_config().external_remediation_probes:
            if not probe_config.enabled:
                logging.info(f"external remediation probe {probe_config.name} disabled")
                continue
            yield ExternalRemediationCheckWorker(load_probe_from_config(probe_config))
