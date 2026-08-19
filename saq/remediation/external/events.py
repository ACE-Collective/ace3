"""Adapters that turn ``ExternalRemediationCheck`` rows into ``RemediationEvent``
objects for :func:`saq.remediation.timeline.gather_remediation_events`."""
from datetime import datetime, timedelta, timezone
import json
import logging
from dataclasses import dataclass
from typing import Optional

from saq.database.model import ExternalRemediationCheck
from saq.remediation.external.types import CheckResult, CheckStatus
from saq.remediation.timeline import RemediationEvent
from saq.util.time import calculate_backoff_delay


def event_to_payload_dict(event: RemediationEvent) -> dict:
    """Serialize a :class:`RemediationEvent` to the dict shape that
    :attr:`ProbeOutcome.found_events` expects.

    Round-trips losslessly through ``events_json`` via :func:`_parse_event_dict`.
    Probes call this when building their outcome so the wire format is owned by
    core ACE rather than each integration."""
    return {
        "source": event.source,
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "description": event.description,
        "event_time": event.event_time.isoformat() if event.event_time else None,
        "actor": event.actor,
        "target": event.target,
        "folder": event.folder,
        "portal_url": event.portal_url,
        "metadata": dict(event.metadata) if event.metadata else {},
    }


def _parse_event_dict(raw: dict) -> Optional[RemediationEvent]:
    """Turn a single serialized event dict into a :class:`RemediationEvent`.

    Returns None (and logs) if the payload is malformed — one bad event must
    not poison an alert page render."""
    try:
        timestamp = raw["timestamp"]
        if isinstance(timestamp, str):
            # Accept ISO strings with Z; datetime.fromisoformat handles offsets
            # post-3.11 but not bare "Z", so normalize.
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError) as exc:
        logging.warning(f"skipping malformed external-check event (timestamp): {exc}")
        return None

    event_time = raw.get("event_time")
    if isinstance(event_time, str):
        try:
            event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        except ValueError:
            event_time = None

    try:
        return RemediationEvent(
            source=raw["source"],
            event_type=raw["event_type"],
            timestamp=timestamp,
            description=raw["description"],
            event_time=event_time,
            actor=raw.get("actor"),
            target=raw.get("target"),
            folder=raw.get("folder"),
            portal_url=raw.get("portal_url"),
            metadata=raw.get("metadata") or {},
        )
    except KeyError as exc:
        logging.warning(f"skipping malformed external-check event (missing field): {exc}")
        return None


def events_from_check(check: ExternalRemediationCheck) -> list[RemediationEvent]:
    """Deserialize ``events_json`` from a CONFIRMED row."""
    if check.result != CheckResult.CONFIRMED.value or not check.events_json:
        return []
    try:
        raw_events = json.loads(check.events_json)
    except (TypeError, ValueError) as exc:
        logging.warning(f"external_remediation_check.id={check.id} has unparseable events_json: {exc}")
        return []
    if not isinstance(raw_events, list):
        logging.warning(
            f"external_remediation_check.id={check.id} events_json is not a list"
        )
        return []
    out: list[RemediationEvent] = []
    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        event = _parse_event_dict(raw)
        if event is not None:
            out.append(event)
    return out


@dataclass(frozen=True)
class ProbeFooterEntry:
    """One row in the alert-page footer that follows the Remediation Timeline."""
    probe_name: str
    pending: int           # rows currently NEW or IN_PROGRESS
    confirmed: int         # COMPLETED + CONFIRMED
    not_found: int         # COMPLETED + NOT_FOUND
    expired: int
    errored: int
    cancelled: int
    superseded: int        # COMPLETED + SUPERSEDED (another probe/ACE confirmed first)
    last_attempt_at: Optional[datetime]    # max(update_time) across this probe's rows for the alert
    next_attempt_at: Optional[datetime]    # min(update_time + backoff) for in-flight rows; None if none pending


@dataclass(frozen=True)
class ProbeFooter:
    """Aggregated status across all probes for one alert. ``entries`` is empty
    if no checks have been queued for this alert."""
    entries: list[ProbeFooterEntry]

    @property
    def any_pending(self) -> bool:
        return any(e.pending > 0 for e in self.entries)


def summarize_alert_checks(
    checks: list[ExternalRemediationCheck],
    *,
    initial_retry_delay_seconds: int = 60,
    max_retry_delay_seconds: int = 3600,
    now: Optional[datetime] = None,
) -> ProbeFooter:
    """Build the per-probe footer summary the template renders."""
    if now is None:
        now = datetime.now(timezone.utc)

    by_probe: dict[str, list[ExternalRemediationCheck]] = {}
    for c in checks:
        by_probe.setdefault(c.probe_name, []).append(c)

    entries: list[ProbeFooterEntry] = []
    for probe_name, group in sorted(by_probe.items()):
        pending = sum(1 for c in group if c.status != CheckStatus.COMPLETED.value)
        confirmed = sum(1 for c in group if c.result == CheckResult.CONFIRMED.value)
        not_found = sum(1 for c in group if c.result == CheckResult.NOT_FOUND.value)
        expired = sum(1 for c in group if c.result == CheckResult.EXPIRED.value)
        errored = sum(1 for c in group if c.result == CheckResult.ERROR.value)
        cancelled = sum(1 for c in group if c.result == CheckResult.CANCELLED.value)
        superseded = sum(1 for c in group if c.result == CheckResult.SUPERSEDED.value)

        last_attempts = [c.update_time for c in group if c.update_time is not None]
        last_attempt_at = max(last_attempts) if last_attempts else None
        if last_attempt_at is not None and last_attempt_at.tzinfo is None:
            last_attempt_at = last_attempt_at.replace(tzinfo=timezone.utc)

        # Project next attempt for in-flight rows from their per-row backoff.
        next_candidates: list[datetime] = []
        for c in group:
            if c.status == CheckStatus.COMPLETED.value:
                continue
            delay = calculate_backoff_delay(
                c.retry_count,
                initial_retry_delay_seconds,
                max_retry_delay_seconds,
            )
            base = c.update_time or c.insert_date
            if base is None:
                continue
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
            next_candidates.append(base + timedelta(seconds=delay))
        next_attempt_at = min(next_candidates) if next_candidates else None

        entries.append(ProbeFooterEntry(
            probe_name=probe_name,
            pending=pending,
            confirmed=confirmed,
            not_found=not_found,
            expired=expired,
            errored=errored,
            cancelled=cancelled,
            superseded=superseded,
            last_attempt_at=last_attempt_at,
            next_attempt_at=next_attempt_at,
        ))
    return ProbeFooter(entries=entries)
