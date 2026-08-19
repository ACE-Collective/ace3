"""Daemon thread that pulls eligible external remediation checks from the DB
and dispatches them to per-probe workers.

Modeled on :mod:`saq.file_collection.collector` — same UUID-lock pattern, same
per-row exponential backoff. The differences are (a) we filter rows by
:attr:`ExternalRemediationCheck.deadline` rather than a time-from-insert
offset, and (b) we don't need a per-row alert lookup since the work item
doesn't carry a storage_dir.
"""
from datetime import UTC, datetime
import json
import logging
from threading import Event, Thread
from typing import Optional
from uuid import uuid4

from sqlalchemy import or_, text
from sqlalchemy.sql import func

from saq.database.model import ExternalRemediationCheck
from saq.database.pool import get_db, remove_all_sessions
from saq.error.reporting import report_exception
from saq.remediation.external.interface import CheckListener
from saq.remediation.external.types import CheckStatus, CheckWorkItem
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


class ExternalRemediationCheckCollector:
    """Collector daemon. One instance per service, dispatches to per-probe
    workers registered via :meth:`register_listener`."""

    collector_thread: Thread

    def __init__(
        self,
        lock_timeout_seconds: int = 300,
        # Fallback backoff for listeners that don't expose per-probe delays;
        # workers report their probe's initial_delay_seconds/max_delay_seconds
        # through CheckListener.get_backoff_delays.
        initial_retry_delay_seconds: int = 60,
        max_retry_delay_seconds: int = 3600,
        loop_interval_seconds: int = 1,
    ):
        self.lock_timeout_seconds = lock_timeout_seconds
        self.initial_retry_delay_seconds = initial_retry_delay_seconds
        self.max_retry_delay_seconds = max_retry_delay_seconds
        self.loop_interval_seconds = loop_interval_seconds
        self.collector_startup_event = Event()
        self.shutdown_event = Event()
        self.listeners: dict[str, CheckListener] = {}

    def start(self):
        self.collector_thread = Thread(
            target=self.collection_loop,
            name="External Remediation Check Collector",
        )
        self.collector_thread.start()

    def start_single_threaded(self):
        self.shutdown_event.set()
        self.collection_loop()

    def wait_for_start(self, timeout: float) -> bool:
        if not self.collector_startup_event.wait(timeout):
            logging.error("external remediation check collector did not start")
            return False
        return True

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        self.collector_thread.join()

    def register_listener(self, name: str, listener: CheckListener):
        if name in self.listeners:
            raise ValueError(f"external remediation check listener {name} already registered")
        self.listeners[name] = listener

    def notify_listeners(self, work_item: CheckWorkItem):
        if work_item.probe_name not in self.listeners:
            raise ValueError(
                f"external remediation probe {work_item.probe_name} not registered"
            )
        self.listeners[work_item.probe_name].handle_external_check_request(work_item)

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

    def collect_work_items(self) -> list[CheckWorkItem]:
        """Find rows that are:
        - owned by a registered probe,
        - not COMPLETED,
        - not within their deadline,
        - either unlocked or whose lock has timed out,
        - past their per-row exponential-backoff delay.
        Then atomically lock them with a fresh UUID and return work items."""
        lock_uuid = str(uuid4())

        query = get_db().query(ExternalRemediationCheck)
        query = query.filter(ExternalRemediationCheck.probe_name.in_(self.listeners.keys()))
        query = query.filter(
            or_(
                ExternalRemediationCheck.lock == None,  # noqa: E711
                func.NOW() >= func.DATE_ADD(
                    ExternalRemediationCheck.lock_time,
                    text(f"INTERVAL {self.lock_timeout_seconds} SECOND"),
                ),
            )
        )
        query = query.filter(ExternalRemediationCheck.status != CheckStatus.COMPLETED.value)
        # Deadline cutoff — past-deadline rows are picked up here and the worker
        # transitions them to COMPLETED/EXPIRED on its next attempt. We
        # deliberately include past-deadline rows so the worker can finalize
        # them; the candidate filter `deadline > NOW()` happens at the
        # eligibility step further down.
        query = query.order_by(ExternalRemediationCheck.insert_date.desc())

        candidates = query.all()

        ready: list[ExternalRemediationCheck] = []
        now = datetime.now(UTC)
        for c in candidates:
            # Always pull past-deadline rows so the worker can mark them EXPIRED.
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

        target_ids = [c.id for c in ready]
        if not target_ids:
            return []

        update = ExternalRemediationCheck.__table__.update().values(
            lock=lock_uuid,
            lock_time=datetime.now(UTC),
            status=CheckStatus.IN_PROGRESS.value,
        ).where(ExternalRemediationCheck.id.in_(target_ids))
        get_db().execute(update)
        get_db().commit()

        locked = (
            get_db()
            .query(ExternalRemediationCheck)
            .filter(ExternalRemediationCheck.lock == lock_uuid)
            .order_by(ExternalRemediationCheck.insert_date.desc())
            .all()
        )
        return [build_work_item(row) for row in locked]

    def collection_loop(self):
        self.collector_startup_event.set()
        while True:
            try:
                for work_item in self.collect_work_items():
                    self.notify_listeners(work_item)
            except Exception as e:
                logging.error(f"error collecting external remediation checks: {e}")
                report_exception()
            finally:
                try:
                    remove_all_sessions()
                except Exception as e:
                    logging.error(f"error removing database connection: {e}")
                    report_exception()

            if self.shutdown_event.is_set():
                break

            self.shutdown_event.wait(self.loop_interval_seconds)
