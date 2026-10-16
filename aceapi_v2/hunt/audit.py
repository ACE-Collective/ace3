"""The audit trail of hunt validation, and the outcome a request leaves.

One HUNT_AUDIT JSON line per request on the ace.hunt_audit logger, in the shape the AI
investigation API uses for its own trail (aceapi_ai/audit.py). Hunt validation runs data-source
queries, sandboxed scripts and alert creation for anyone holding a hunt:write key, which includes
an analyst's AI-scoped key, so the point of the trail is reconstructing what each key asked for.
The container's log pipeline ships it off-box like any other log line; the routes write it outside
suppress_external_logging(), which would otherwise drop it.

Kept apart from service.py, which imports the hunter: this module is cheap to import anywhere.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

audit_logger = logging.getLogger("ace.hunt_audit")


@dataclass
class ValidationOutcome:
    """What a validation request answers, and what its audit record says. The caller creates it,
    so that a request that raises can still be audited with what it had done."""
    body: dict = field(default_factory=dict)
    status: int = 500
    # what the request did, for the audit record
    audit: dict[str, Any] = field(default_factory=dict)
    started: float = field(default_factory=time.monotonic)


def write_audit_record(event: str, *, user: Optional[str], user_id: Optional[int], key_id: Optional[int],
                       key_name: Optional[str], src_ip: Optional[str], **fields: Any) -> None:
    record = {
        "event": event,
        "user": user,
        "user_id": user_id,
        "key_id": key_id,
        "key_name": key_name,
        "src_ip": src_ip,
    }
    record.update(fields)
    audit_logger.info("HUNT_AUDIT %s", json.dumps(record, default=str))


def audit_fields(outcome: ValidationOutcome) -> tuple[str, dict[str, Any]]:
    """The audit event and fields of an answered request."""
    if outcome.status == 200:
        event = "hunt_validate"
    else:
        # an execution failure says so; anything else refused the request before it ran
        event = outcome.audit.pop("event", "hunt_rejected")

    return event, {
        "status": outcome.status,
        "detail": outcome.body.get("error"),
        "duration_ms": int((time.monotonic() - outcome.started) * 1000),
        **outcome.audit,
    }


def failure_audit_fields(outcome: ValidationOutcome, error: BaseException) -> tuple[str, dict[str, Any]]:
    """The audit event and fields of a request that raised."""
    return outcome.audit.pop("event", "hunt_rejected"), {
        "status": 500,
        "detail": f"{type(error).__name__}: {error}",
        "duration_ms": int((time.monotonic() - outcome.started) * 1000),
        **outcome.audit,
    }
