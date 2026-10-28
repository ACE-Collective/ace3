"""Which external remediation checks are due, for the queue service in
:mod:`saq.queue_service`. Unlike file collection, a row's cutoff is its
:attr:`ExternalRemediationCheck.deadline` rather than a time-from-insert
offset, and a row past it is still handed out so the worker can finalize it.
"""
from datetime import UTC, datetime
import json
import logging
from typing import Optional

from saq.database.model import ExternalRemediationCheck
from saq.queue_service import QueueCollector
from saq.remediation.external.types import CheckWorkItem
from saq.util.time import calculate_backoff_delay


def _decode_context(row: ExternalRemediationCheck) -> Optional[dict]:
    """Deserialize ``context_json`` into a dict, defensively.

    NULL → None (the common case for legacy rows and probes that don't use
    context). Malformed JSON or a non-dict payload is logged and treated as
    None so one bad row can't poison the queue.
    """
    raw = row.context_json
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        logging.warning(
            "external_remediation_check.id=%d has unparseable context_json: %s",
            row.id, exc,
        )
        return None
    if not isinstance(value, dict):
        logging.warning(
            "external_remediation_check.id=%d context_json is not a dict (got %s)",
            row.id, type(value).__name__,
        )
        return None
    return value


def build_work_item(row: ExternalRemediationCheck) -> CheckWorkItem:
    return CheckWorkItem(
        id=row.id,
        probe_name=row.probe_name,
        observable_type=row.observable_type,
        observable_value=row.observable_value,
        alert_uuid=row.alert_uuid,
        retry_count=row.retry_count,
        max_retries=row.max_retries,
        deadline=row.deadline,
        context=_decode_context(row),
    )


class ExternalRemediationCheckCollector(QueueCollector[CheckWorkItem]):
    """Collector daemon. One instance per service, dispatches to per-probe
    workers registered via :meth:`register_listener`."""

    model = ExternalRemediationCheck
    name_column = "probe_name"
    label = "external remediation check"

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        # Fallback backoff for listeners that don't expose per-probe delays;
        # workers report their probe's initial_delay_seconds/max_delay_seconds
        # through get_backoff_delays.
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
        loop_interval_seconds: int = 1,
    ):
        super().__init__(lock_timeout_seconds=lock_timeout_seconds, loop_interval_seconds=loop_interval_seconds)
        self.initial_retry_delay_seconds = initial_retry_delay_seconds
        self.max_retry_delay_seconds = max_retry_delay_seconds

    def _backoff_delays(self, probe_name: str) -> tuple[int, int]:
        """The (initial, max) retry delay for a probe's rows.

        Sourced from the registered listener's probe configuration so the
        per-probe initial_delay_seconds/max_delay_seconds settings actually
        govern the schedule; the collector-level values are only the fallback
        for listeners that don't expose delays (e.g. test doubles).
        """
        listener = self.listeners.get(probe_name)
        get_delays = getattr(listener, "get_backoff_delays", None)
        if callable(get_delays):
            return get_delays()
        return (self.initial_retry_delay_seconds, self.max_retry_delay_seconds)

    def ready(self, rows: list[ExternalRemediationCheck]) -> list[ExternalRemediationCheck]:
        """Rows past their per-row exponential-backoff delay, and every row
        past its deadline, so the worker can mark it EXPIRED."""
        ready: list[ExternalRemediationCheck] = []
        now = datetime.now(UTC)
        for c in rows:
            deadline = c.deadline
            if deadline is not None and deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            past_deadline = deadline is not None and deadline <= now

            if past_deadline:
                ready.append(c)
                continue

            required_delay = calculate_backoff_delay(c.retry_count, *self._backoff_delays(c.probe_name))
            if c.update_time is None:
                ready.append(c)
                continue
            update_time = c.update_time
            if update_time.tzinfo is None:
                update_time = update_time.replace(tzinfo=UTC)
            if (now - update_time).total_seconds() >= required_delay:
                ready.append(c)

        return ready

    def build_work_item(self, row: ExternalRemediationCheck) -> CheckWorkItem:
        return build_work_item(row)
