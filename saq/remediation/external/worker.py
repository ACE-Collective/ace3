"""Worker pool that executes one probe per item, then delegates persistence to
:mod:`saq.remediation.external.persistence`.

Mirrors :mod:`saq.file_collection.worker`. The decision rules
(FOUND_EVENTS/NOT_FOUND/PENDING/TRANSIENT_ERROR → row state) live in the
persistence helper so that synchronous-first-probe callers (analysis modules)
make identical writes.
"""
from datetime import UTC, datetime, timedelta
import logging
from queue import Empty, Queue
from threading import Event, Thread
from typing import Optional

from saq.error.reporting import report_exception
from saq.remediation.external.database import find_superseding_confirmation
from saq.remediation.external.interface import CheckListener
from saq.remediation.external.persistence import (
    finalize_expired,
    finalize_superseded,
    persist_probe_outcome,
)
from saq.remediation.external.probe import ExternalRemediationProbe
from saq.remediation.external.types import (
    CheckWorkItem,
    ProbeOutcome,
    ProbeOutcomeKind,
    ProbeTarget,
)


class ExternalRemediationCheckWorker(CheckListener):
    """One worker = one probe = N threads pulling from a shared in-memory queue."""

    def __init__(self, probe: ExternalRemediationProbe):
        self.probe = probe
        self.work_queue: Queue[CheckWorkItem] = Queue()
        self.worker_threads: list[Thread] = []
        self.startup_events: list[Event] = []
        self.shutdown_event = Event()
        self.queue_wait_timeout = 1

    def get_backoff_delays(self) -> tuple[int, int]:
        """The probe's configured retry backoff, consumed by the collector's
        eligibility check."""
        return (self.probe.initial_delay_seconds, self.probe.max_delay_seconds)

    def handle_external_check_request(self, work_item: CheckWorkItem):
        if work_item.probe_name != self.probe.name:
            raise ValueError(
                f"probe name {work_item.probe_name} does not match worker probe {self.probe.name}"
            )
        logging.info(
            f"received external remediation check for {self.probe.name} "
            f"{work_item.observable_type} {work_item.observable_value}"
        )
        self.work_queue.put(work_item)

    def start(self):
        logging.info(
            f"starting {self.probe.thread_count} threads for probe {self.probe.name}"
        )
        for index in range(self.probe.thread_count):
            startup_event = Event()
            self.startup_events.append(startup_event)
            thread = Thread(
                target=self.worker_loop,
                name=f"ExternalRemediationCheckWorker-{self.probe.name}-{index}",
                args=(startup_event,),
            )
            self.worker_threads.append(thread)
            thread.start()

    def start_single_threaded(self):
        self.stop()
        self.worker_loop(Event())

    def wait_for_start(self, timeout: float) -> bool:
        for index, ev in enumerate(self.startup_events):
            if not ev.wait(timeout):
                logging.error(f"probe worker {self.probe.name}/{index} did not start")
                return False
        return True

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        for thread in self.worker_threads:
            thread.join()

    def worker_loop(self, startup_event: Event):
        startup_event.set()
        while True:
            work: Optional[CheckWorkItem] = None
            try:
                work = self.work_queue.get(timeout=self.queue_wait_timeout)
            except Empty:
                pass

            try:
                if work:
                    self.process(work)
            except Exception as e:
                logging.error(f"error processing external remediation check: {e}")
                report_exception()

            if self.shutdown_event.is_set():
                break

    def process(self, work: CheckWorkItem):
        """Run one probe attempt for ``work`` and persist the outcome."""
        now = datetime.now(UTC)

        # Deadline guard: rows whose deadline has passed are finalized as
        # EXPIRED without calling the probe (no point asking the vendor again).
        deadline = work.deadline
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        if deadline <= now:
            finalize_expired(work.id, now=now)
            return

        # Supersession guard: if another probe (or an ACE remediation) confirmed this target's
        # remediation long enough ago (the grace window covers the vendor's own late-surfacing
        # events), the email is gone -- finalize without spending a vendor API call.
        superseded_reason = find_superseding_confirmation(
            observable_type=work.observable_type,
            observable_value=work.observable_value,
            exclude_probe_name=work.probe_name,
            confirmed_before=now - timedelta(seconds=self.probe.supersede_grace_seconds),
        )
        if superseded_reason is not None:
            finalize_superseded(work.id, superseded_reason, now=now)
            return

        target = ProbeTarget(
            observable_type=work.observable_type,
            observable_value=work.observable_value,
            alert_uuid=work.alert_uuid,
            deadline=work.deadline,
            retry_count=work.retry_count,
            max_retries=work.max_retries,
            context=work.context,
        )

        logging.info(
            f"STARTED probing {self.probe.name} for {work.observable_type} "
            f"{work.observable_value} (attempt {work.retry_count + 1}/{work.max_retries})"
        )

        try:
            outcome = self.probe.probe(target)
        except Exception as e:
            outcome = ProbeOutcome(
                transient_error=f"{e.__class__.__name__}: {e}",
                message=f"probe raised {e.__class__.__name__}",
            )
            logging.error(f"probe {self.probe.name} raised: {e}")

        persist_probe_outcome(
            work.id,
            outcome,
            retry_count=work.retry_count,
            max_retries=work.max_retries,
            now=now,
        )

        kind = outcome.kind
        if kind is ProbeOutcomeKind.FOUND_EVENTS:
            logging.info(
                f"CONFIRMED {self.probe.name} {work.observable_type} {work.observable_value} "
                f"with {len(outcome.found_events or [])} event(s)"
            )
        elif kind is ProbeOutcomeKind.NOT_FOUND:
            logging.info(
                f"NOT_FOUND {self.probe.name} {work.observable_type} {work.observable_value}"
            )
        elif kind is ProbeOutcomeKind.PENDING:
            logging.info(
                f"PENDING {self.probe.name} {work.observable_type} {work.observable_value} "
                f"(attempt {work.retry_count + 1}/{work.max_retries})"
            )
        else:
            logging.warning(
                f"ERROR {self.probe.name} {work.observable_type} {work.observable_value}: "
                f"{outcome.transient_error or outcome.permanent_error}"
            )
