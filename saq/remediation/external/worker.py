"""Executes one probe per item, then delegates persistence to
:mod:`saq.remediation.external.persistence`.

The decision rules (FOUND_EVENTS/NOT_FOUND/PENDING/TRANSIENT_ERROR → row
state) live in the persistence helper so that synchronous-first-probe callers
(analysis modules) make identical writes.
"""
from datetime import UTC, datetime, timedelta
import logging

from saq.queue_service import QueueWorker
from saq.remediation.external.database import find_superseding_confirmation
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


class ExternalRemediationCheckWorker(QueueWorker[CheckWorkItem]):
    """One worker = one probe = N threads pulling from a shared in-memory queue."""

    def __init__(self, probe: ExternalRemediationProbe):
        super().__init__()
        self.probe = probe

    @property
    def name(self) -> str:
        return self.probe.name

    @property
    def thread_count(self) -> int:
        return self.probe.thread_count

    def get_backoff_delays(self) -> tuple[int, int]:
        """The probe's configured retry backoff, consumed by the collector's
        eligibility check."""
        return (self.probe.initial_delay_seconds, self.probe.max_delay_seconds)

    def describe(self, work_item: CheckWorkItem) -> str:
        return (
            f"external remediation check {work_item.id} ({work_item.probe_name} "
            f"{work_item.observable_type} {work_item.observable_value})"
        )

    def log_extra(self, work_item: CheckWorkItem) -> dict:
        return {"alert_uuid": work_item.alert_uuid}

    def process_one(self, work_item: CheckWorkItem):
        self.process(work_item)

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
