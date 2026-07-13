"""Remediation timeline aggregation.

A small, generic mechanism that lets any Analysis subclass publish chronological
"remediation events" (e.g., what an email-security platform did to a message),
and lets the alert UI render them as a unified timeline regardless of which
platform produced them.

Three pieces:
- ``RemediationEvent``: a platform-agnostic record of one event.
- ``RemediationEventProvider``: the duck-typed protocol an Analysis implements
  to contribute events.
- ``gather_remediation_events()``: walks an alert's analysis tree and returns
  all events from all providers, sorted the way the UI table reads: by
  ``event_time``, then ``timestamp``, then ``target`` — all compared at the
  whole-second precision the table displays.

The aggregator is intentionally tolerant: any provider exception or unparseable
event is logged and skipped so a misbehaving integration cannot prevent the
alert page from rendering.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging
from typing import TYPE_CHECKING, Optional, Protocol, runtime_checkable

from saq.constants import F_EMAIL_DELIVERY, parse_email_delivery

if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis


def _format_duration(td: timedelta) -> str:
    """Render a timedelta as a compact ``"1d 4h"`` / ``"5m 22s"`` style string.

    Returns ``"0s"`` for zero/negative durations (defensive — providers should
    not emit events whose ``timestamp`` precedes their ``event_time``, but the
    UI shouldn't render a confusing minus sign if they do).
    """
    total = int(td.total_seconds())
    if total <= 0:
        return "0s"
    if total < 60:
        return f"{total}s"
    if total < 3600:
        m, s = divmod(total, 60)
        return f"{m}m {s}s" if s else f"{m}m"
    if total < 86400:
        h, rem = divmod(total, 3600)
        m = rem // 60
        return f"{h}h {m}m" if m else f"{h}h"
    d, rem = divmod(total, 86400)
    h = rem // 3600
    return f"{d}d {h}h" if h else f"{d}d"


def _display_precision(dt: datetime) -> datetime:
    """Truncate to whole seconds — the precision the timeline template renders.

    The UI formats both datetime columns with ``strftime('%Y-%m-%d %H:%M:%S')``.
    Sorting on the full-precision values makes rows that *look* tied sort by an
    invisible sub-second component, so the visible tiebreaker columns never get
    consulted. Truncating (not rounding) here matches strftime exactly.
    """
    return dt.replace(microsecond=0)


@dataclass
class RemediationEvent:
    """One chronological event in an email's remediation history."""

    source: str
    """Platform that produced the event (e.g. ``"microsoft_defender"``)."""

    event_type: str
    """Machine-readable event identifier (e.g. ``"auto_remediated"``, ``"detected"``)."""

    timestamp: datetime
    """When the event occurred (UTC)."""

    description: str
    """Short human-readable summary shown in the UI."""

    event_time: Optional[datetime] = None
    """When the underlying message was originally received (UTC).

    Used to compute how long it took the platform to react. Optional because a
    standalone observable may not have this context.
    """

    actor: Optional[str] = None
    """Optional label for what entity acted (e.g. ``"ZAP"``, ``"Auto-Remediated"``)."""

    target: Optional[str] = None
    """Optional label for what was acted on — for email events, the recipient
    address (e.g. ``"alice@example.com"``). Used by the timeline UI's Target
    column when an alert covers multiple email_delivery observables."""

    folder: Optional[str] = None
    """Optional final mailbox folder after the event (e.g. ``"Junk"``)."""

    portal_url: Optional[str] = None
    """Optional link to the platform's UI for this message/event."""

    metadata: dict = field(default_factory=dict)
    """Optional platform-specific extras the UI does not rely on."""

    def __post_init__(self):
        # Different providers hand us different datetime flavors: MySQL TIMESTAMP
        # columns (e.g. RemediationHistory.insert_date) come back tz-naive, while
        # ISO strings parsed from JSON or APIs come back tz-aware. Mixing the
        # two raises TypeError on arithmetic. Normalize to tz-aware UTC here so
        # downstream code (duration, sort key, template formatters) never has
        # to think about it.
        if self.timestamp is not None and self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        if self.event_time is not None and self.event_time.tzinfo is None:
            self.event_time = self.event_time.replace(tzinfo=timezone.utc)

    @property
    def duration(self) -> Optional[timedelta]:
        """Time elapsed between ``event_time`` and ``timestamp``."""
        if self.event_time is None:
            return None
        return self.timestamp - self.event_time

    @property
    def duration_display(self) -> Optional[str]:
        """Human-readable duration (``"5m 22s"``, ``"1d 4h"``, etc.)."""
        td = self.duration
        return _format_duration(td) if td is not None else None


@runtime_checkable
class RemediationEventProvider(Protocol):
    """Protocol an Analysis implements to publish events into the timeline.

    Provider classes call ``register_remediation_event_provider()`` once at
    import time. The aggregator looks them up by class type via
    ``RootAnalysis.get_analysis_by_type()``, which is bounded by the number of
    registered providers (a handful) rather than the size of the alert tree.
    """

    def get_remediation_events(self) -> list[RemediationEvent]: ...


# Registered Analysis subclasses that publish RemediationEvents. Modules call
# ``register_remediation_event_provider(cls)`` at import time. The aggregator
# only inspects (and only loads details for) instances of these classes — never
# arbitrary analyses in the alert tree, no matter how big the alert.
REGISTERED_REMEDIATION_PROVIDERS: list[type] = []


def register_remediation_event_provider(analysis_class: type) -> None:
    """Register an Analysis subclass that produces ``RemediationEvent`` objects.

    Idempotent: calling twice with the same class is a no-op.
    """
    if analysis_class not in REGISTERED_REMEDIATION_PROVIDERS:
        REGISTERED_REMEDIATION_PROVIDERS.append(analysis_class)


def gather_remediation_events(
    root: "RootAnalysis",
    *,
    fallback_event_time: Optional[datetime] = None,
) -> list[RemediationEvent]:
    """Collect every RemediationEvent for an alert.

    Sources, in order:

    1. **Analysis-tree providers.** Any ``Analysis`` subclass in ``root.all_analysis``
       that exposes a ``get_remediation_events()`` method.
    2. **ACE's own remediation attempts.** Each row in ``remediation_history``
       whose parent ``Remediation`` targets an ``email_delivery`` observable in
       this alert. ``fallback_event_time`` (typically ``alert.event_time``) is
       used as the ``event_time`` on these events because ACE doesn't store the
       email's ``received_time``.

    Returns events sorted by ``event_time`` ascending, then ``timestamp``
    ascending, then ``target``. Both datetimes are compared truncated to whole
    seconds — the precision the timeline table renders — so rows that display an
    identical Event Time fall through to the visible tiebreaker columns rather
    than ordering on invisible microseconds. Events lacking ``event_time`` sort
    to the end.

    Cost model: ``load_details()`` reads the analysis details JSON from disk and
    is intentionally avoided on the alert page by default. The aggregator only
    calls it for instances of classes in ``REGISTERED_REMEDIATION_PROVIDERS`` —
    so an alert with 200 analyses but one Module B instance pays for one disk
    read, not 200.
    """
    events: list[RemediationEvent] = []

    for provider_class in REGISTERED_REMEDIATION_PROVIDERS:
        for analysis in root.get_analysis_by_type(provider_class):
            loader = getattr(analysis, "load_details", None)
            if callable(loader):
                try:
                    loader()
                except Exception:
                    logging.exception(
                        "load_details() failed for remediation event provider %s; skipping",
                        provider_class.__name__,
                    )
                    continue

            try:
                produced = analysis.get_remediation_events() or []
            except Exception:
                logging.exception(
                    "remediation event provider %s raised; skipping",
                    provider_class.__name__,
                )
                continue

            for event in produced:
                if isinstance(event, RemediationEvent):
                    events.append(event)
                else:
                    logging.warning(
                        "remediation event provider %s returned non-RemediationEvent %r; skipping",
                        provider_class.__name__, type(event).__name__,
                    )

    # Pull ACE's own email-remediation attempts from the database
    try:
        events.extend(_gather_ace_email_remediation_events(root, fallback_event_time))
    except Exception:
        logging.exception("failed to gather ACE email remediation events; skipping")

    # Pull events confirmed by ``saq/remediation/external/`` probes. These
    # are written by the background daemon after analysis completes, so
    # they may include events that didn't exist when the alert was first analyzed.
    try:
        events.extend(_gather_external_check_events(root))
    except Exception:
        logging.exception("failed to gather external remediation check events; skipping")

    # Sort order matches the table reading order:
    #   1. event_time     (the "Event Time" column — the message's received time)
    #   2. timestamp      (the "When" column — when the action happened)
    #   3. target         (the "Target" column — recipient, breaks ties when
    #                      multiple events fire at the same time on the same
    #                      message but for different recipients)
    #   4. source, description  (final deterministic tiebreakers)
    #
    # The datetimes are compared at *display precision* (whole seconds). Each
    # source resolves event_time from its own authority for the same message —
    # one platform reports a whole second, ACE's fallback carries microseconds
    # through its JSON round-trip — so full-precision comparison makes rows that
    # render as an identical Event Time sort by an invisible sub-second
    # component, and the visible tiebreakers below never get consulted.
    #
    # Coarsening the leading keys produces more exact ties, and the input order
    # is not stable (the remediation_history query has no ORDER BY, and three
    # sources are concatenated). source/description keep a fully-tied set
    # rendering identically on every page load. Every key is a displayed column.
    #
    # Events lacking event_time slot to the bottom of the table — they have no
    # message context to anchor them in the per-message chronology.
    def _sort_key(e: RemediationEvent):
        when = _display_precision(e.timestamp)
        tail = (e.target or "", e.source or "", e.description or "")
        if e.event_time is None:
            return (1, when, when) + tail
        return (0, _display_precision(e.event_time), when) + tail

    events.sort(key=_sort_key)
    return events


def _gather_ace_email_remediation_events(
    root: "RootAnalysis",
    fallback_event_time: Optional[datetime],
) -> list[RemediationEvent]:
    """Return one RemediationEvent per ``remediation_history`` row whose parent
    ``Remediation`` targets an ``email_delivery`` observable in this alert.

    Imports are local to keep the module importable in non-DB-backed contexts.
    """
    from saq.database.model import Remediation, RemediationHistory
    from saq.database.pool import get_db

    keys = sorted({
        obs.value for obs in root.find_observables(lambda o: o.type == F_EMAIL_DELIVERY)
    })
    if not keys:
        return []

    db = get_db()

    remediations = (
        db.query(Remediation)
        .filter(Remediation.type == F_EMAIL_DELIVERY)
        .filter(Remediation.key.in_(keys))
        .all()
    )
    if not remediations:
        return []

    rem_by_id = {r.id: r for r in remediations}

    history_rows = (
        db.query(RemediationHistory)
        .filter(RemediationHistory.remediation_id.in_(rem_by_id.keys()))
        .all()
    )

    events: list[RemediationEvent] = []
    for h in history_rows:
        rem = rem_by_id.get(h.remediation_id)
        if rem is None:
            continue

        action = (rem.action or "").strip()
        result = (h.result or "").strip()
        description = (
            f"{action.capitalize()} ({result.capitalize()})"
            if action and result
            else action.capitalize() or result.capitalize() or "Remediation"
        )

        # Pull the recipient out of the email_delivery key (format `<msgid>|recipient`).
        target: Optional[str] = None
        try:
            _, recipient = parse_email_delivery(rem.key)
            target = recipient or None
        except (ValueError, TypeError, AttributeError):
            pass

        events.append(RemediationEvent(
            source="ACE",
            event_type=f"ace_{action}".lower() if action else "ace",
            timestamp=h.insert_date,
            description=description,
            event_time=fallback_event_time,
            actor=rem.name,
            target=target,
            metadata={
                "remediation_id": rem.id,
                "history_id": h.id,
                "status": h.status,
                "result": h.result,
                "message": h.message,
            },
        ))

    return events


def _gather_external_check_events(root: "RootAnalysis") -> list[RemediationEvent]:
    """Return the events confirmed by external remediation probes for this
    alert. See :mod:`saq.remediation.external` — confirmed rows store a
    serialized ``list[RemediationEvent]`` in ``events_json``."""
    from saq.remediation.external.database import get_external_checks_for_alert
    from saq.remediation.external.events import events_from_check

    checks = get_external_checks_for_alert(root.uuid)
    out: list[RemediationEvent] = []
    for check in checks:
        out.extend(events_from_check(check))
    return out
