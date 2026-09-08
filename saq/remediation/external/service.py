"""ACE service that runs the external-remediation-check daemon.

The disposition sweep is intentionally optional and off by default (per the
design decision recorded with this work): closing an alert should not stop
late-arriving confirmations from landing on its timeline.
"""
import logging
import threading
from typing import Type

from pydantic import Field
from sqlalchemy import distinct

from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_EXTERNAL_REMEDIATION_CHECK
from saq.database.model import Alert, ExternalRemediationCheck
from saq.database.pool import get_db, remove_all_sessions
from saq.error.reporting import log_loop_exception
from saq.remediation.external.database import cancel_external_checks_for_alert
from saq.remediation.external.manager import ExternalRemediationCheckManager
from saq.remediation.external.types import CheckStatus
from saq.service import ACEServiceInterface


class ExternalRemediationCheckServiceConfig(ServiceConfig):
    lock_timeout_seconds: int = Field(
        default=300,
        description="How long a row may stay locked by a worker before another may claim it.",
    )
    initial_retry_delay_seconds: int = Field(
        default=60,
        description="Initial per-row backoff between PENDING / transient-error attempts.",
    )
    max_retry_delay_seconds: int = Field(
        default=3600,
        description="Maximum per-row backoff (1 hour default).",
    )
    stop_on_disposition: bool = Field(
        default=False,
        description=(
            "If true, periodically cancel in-flight checks for alerts that "
            "have been dispositioned. Default false so late confirmations "
            "still land on closed alerts."
        ),
    )
    disposition_sweep_interval_seconds: int = Field(
        default=300,
        description="How often the disposition sweep runs (only if stop_on_disposition).",
    )


class ExternalRemediationCheckService(ACEServiceInterface):

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ExternalRemediationCheckServiceConfig

    def start(self):
        config = get_service_config(SERVICE_EXTERNAL_REMEDIATION_CHECK)
        self.manager = ExternalRemediationCheckManager(
            lock_timeout_seconds=config.lock_timeout_seconds,
            initial_retry_delay_seconds=config.initial_retry_delay_seconds,
            max_retry_delay_seconds=config.max_retry_delay_seconds,
        )
        self.manager.start()

        self._sweep_thread = None
        self._sweep_shutdown = threading.Event()
        if config.stop_on_disposition:
            self._sweep_thread = threading.Thread(
                target=self._disposition_sweep_loop,
                args=(config.disposition_sweep_interval_seconds,),
                name="ExternalRemediationCheckDispositionSweep",
                daemon=True,
            )
            self._sweep_thread.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.manager.wait_for_start(timeout)

    def start_single_threaded(self):
        self.manager.start_single_threaded()

    def stop(self):
        self._sweep_shutdown.set()
        self.manager.stop()

    def wait(self):
        self.manager.wait()
        if self._sweep_thread is not None:
            self._sweep_thread.join()

    def _disposition_sweep_loop(self, interval_seconds: int):
        """Cancel checks whose alert has been dispositioned."""
        while not self._sweep_shutdown.is_set():
            try:
                self._run_disposition_sweep()
            except Exception as e:
                log_loop_exception(e, "disposition sweep failed")
            finally:
                try:
                    remove_all_sessions()
                except Exception:
                    pass
            self._sweep_shutdown.wait(interval_seconds)

    def _run_disposition_sweep(self):
        # Find alerts that are dispositioned and still have in-flight checks.
        # Join on alert_uuid so we only ever touch checks whose owning alert
        # exists and is dispositioned — orphaned checks are left alone.
        active_alert_uuids = (
            get_db()
            .query(distinct(ExternalRemediationCheck.alert_uuid))
            .filter(ExternalRemediationCheck.status != CheckStatus.COMPLETED.value)
            .all()
        )
        if not active_alert_uuids:
            return

        uuids = [row[0] for row in active_alert_uuids]
        dispositioned = (
            get_db()
            .query(Alert.uuid)
            .filter(Alert.uuid.in_(uuids))
            .filter(Alert.disposition != None)  # noqa: E711
            .all()
        )

        cancelled = 0
        for (alert_uuid,) in dispositioned:
            cancelled += cancel_external_checks_for_alert(alert_uuid)
        if cancelled:
            logging.info(f"disposition sweep cancelled {cancelled} external check rows")
