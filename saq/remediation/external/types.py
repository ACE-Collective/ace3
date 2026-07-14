from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class CheckStatus(Enum):
    """Mirrors the ``status`` column on ``external_remediation_check``."""
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class CheckResult(Enum):
    """Terminal results recorded on ``external_remediation_check.result``.

    A row remains at ``result IS NULL`` while it is still being polled.
    """
    CONFIRMED = "CONFIRMED"       # probe found events — store them and stop
    NOT_FOUND = "NOT_FOUND"       # probe says the target does not exist
    EXPIRED = "EXPIRED"           # deadline reached without confirmation
    ERROR = "ERROR"               # ran out of retries on transient errors
    CANCELLED = "CANCELLED"       # manually cancelled (e.g. disposition sweep)


class ProbeOutcomeKind(Enum):
    """The five shapes a single probe attempt can return."""
    FOUND_EVENTS = "FOUND_EVENTS"           # terminal: events to persist
    NOT_FOUND = "NOT_FOUND"                 # terminal: target does not exist
    PENDING = "PENDING"                     # vendor returned nothing yet — keep polling
    TRANSIENT_ERROR = "TRANSIENT_ERROR"     # retry per backoff, count toward retry_count
    PERMANENT_ERROR = "PERMANENT_ERROR"     # terminal: record result=ERROR immediately, no retries


class ProbeTarget(BaseModel):
    """Inputs handed to a probe for one attempt."""
    observable_type: str
    observable_value: str
    alert_uuid: str
    # Surfaced so probes can log meaningfully and skip work past the deadline.
    deadline: datetime
    retry_count: int = 0
    max_retries: int
    context: Optional[dict] = Field(
        default=None,
        description=(
            "Optional enrichment passed by callers that have richer knowledge "
            "than the daemon (e.g. an analysis module that walked the alert "
            "tree for recipient / received_time). Frozen at queue time on "
            "``external_remediation_check.context_json`` and rehydrated by the "
            "collector, so background re-polls see the same context as the "
            "original synchronous-first call."
        ),
    )


class ProbeOutcome(BaseModel):
    """A single probe attempt's result.

    Exactly one of ``found_events`` / ``not_found`` / ``pending`` /
    ``transient_error`` / ``permanent_error`` describes the outcome (enforced by
    the validator). The ``kind`` property summarizes which one.
    """
    found_events: Optional[list[dict]] = Field(
        default=None,
        description="Serialized RemediationEvent dicts. Presence means CONFIRMED.",
    )
    not_found: bool = False
    pending: bool = False
    transient_error: Optional[str] = None
    permanent_error: Optional[str] = Field(
        default=None,
        description="terminal error — record result=ERROR immediately, no retries",
    )
    message: Optional[str] = Field(
        default=None,
        description="Human-readable note recorded on the check row / history row.",
    )

    @model_validator(mode="after")
    def _exactly_one_outcome(self) -> "ProbeOutcome":
        set_flags = [
            self.found_events is not None,
            self.not_found,
            self.pending,
            self.transient_error is not None,
            self.permanent_error is not None,
        ]
        if sum(1 for f in set_flags if f) != 1:
            raise ValueError(
                "ProbeOutcome must set exactly one of "
                "found_events / not_found / pending / transient_error / permanent_error"
            )
        return self

    @property
    def kind(self) -> ProbeOutcomeKind:
        if self.found_events is not None:
            return ProbeOutcomeKind.FOUND_EVENTS
        if self.not_found:
            return ProbeOutcomeKind.NOT_FOUND
        if self.pending:
            return ProbeOutcomeKind.PENDING
        if self.permanent_error is not None:
            return ProbeOutcomeKind.PERMANENT_ERROR
        return ProbeOutcomeKind.TRANSIENT_ERROR


class CheckWorkItem(BaseModel):
    """One unit of work pulled from the DB and dispatched to a worker."""
    id: int
    probe_name: str
    observable_type: str
    observable_value: str
    alert_uuid: str
    retry_count: int
    max_retries: int
    deadline: datetime
    context: Optional[dict] = None
