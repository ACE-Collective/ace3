# vim: sw=4:ts=4:et:cc=120

"""URL-click timeline aggregation.

A small, source-agnostic mechanism that lets any Analysis subclass publish "click
events" (a user reaching a URL / visiting a domain, as seen in some log source) and
lets the alert UI render them as a single unified table regardless of which source
(Splunk, Logscale, ...) produced them.

Three pieces, mirroring ``saq.remediation.timeline``:
- ``ClickerEvent``: a source-agnostic record of one observed click.
- ``ClickerEventProvider``: the duck-typed protocol an Analysis implements.
- ``gather_clicker_events()``: walks an alert's analysis tree and returns all events
  from all registered providers, sorted by timestamp ascending.

The aggregator is intentionally tolerant: any provider exception or unparseable event
is logged and skipped so a misbehaving source cannot prevent the alert page from
rendering.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from typing import TYPE_CHECKING, Optional, Protocol, runtime_checkable


if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis


@dataclass
class ClickerEvent:
    """One observed click on a URL / visit to a domain."""

    source: str
    """Log source that produced the event (e.g. ``"splunk"``)."""

    timestamp: Optional[datetime]
    """When the click occurred (UTC). May be None if the source omits a time."""

    user: Optional[str] = None
    """The user who clicked (e.g. the mailbox / UPN)."""

    action_type: Optional[str] = None
    """Source action label — the real allowed/blocked signal (e.g. ``ClickAllowed`` /
    ``ClickBlocked`` for MS Defender). Drives display emphasis and escalation."""

    url: Optional[str] = None
    """The per-row matched/clicked value as seen in the source log (e.g. the decoded clicked URL, or
    the full process CommandLine). Drives the fqdn crawl path; not what the URL column shows."""

    searched_value: Optional[str] = None
    """The observable value that was searched (the url/fqdn that received the clicker_detection
    directive). Shown in the URL column for analyst clarity, regardless of source."""

    network_message_id: Optional[str] = None
    """Optional id tying the click back to the originating email."""

    portal_url: Optional[str] = None
    """Optional link that opens the underlying search in the source's UI."""

    metadata: dict = field(default_factory=dict)
    """Optional source-specific extras the UI does not rely on."""

    def __post_init__(self):
        # Normalize to tz-aware UTC so sorting/formatting never mixes naive/aware.
        if self.timestamp is not None and self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)


@runtime_checkable
class ClickerEventProvider(Protocol):
    """Protocol an Analysis implements to publish events into the URL Clicks view.

    Provider classes call ``register_clicker_event_provider()`` once at import time.
    The aggregator looks them up by class type via ``RootAnalysis.get_analysis_by_type()``,
    which is bounded by the number of registered providers (a handful) rather than the
    size of the alert tree.
    """

    def get_clicker_events(self) -> list["ClickerEvent"]: ...


# Registered Analysis subclasses that publish ClickerEvents. Modules call
# ``register_clicker_event_provider(cls)`` at import time. The aggregator only inspects
# (and only loads details for) instances of these classes.
REGISTERED_CLICKER_PROVIDERS: list[type] = []


def register_clicker_event_provider(analysis_class: type) -> None:
    """Register an Analysis subclass that produces ``ClickerEvent`` objects.

    Idempotent: calling twice with the same class is a no-op.
    """
    if analysis_class not in REGISTERED_CLICKER_PROVIDERS:
        REGISTERED_CLICKER_PROVIDERS.append(analysis_class)


@dataclass
class ClickerResults:
    """Aggregated state of clicker detection for an alert, for the URL Clicks view.

    Distinguishes "ran but found nothing" from "never ran": ``ran`` is True whenever a registered
    clicker-provider analysis exists in the tree, regardless of how many events it produced. That
    lets the UI render the URL Clicks card (so analysts can see the searches were performed and came
    back clean) only when detection actually ran.
    """

    events: list[ClickerEvent] = field(default_factory=list)
    """All ClickerEvents from all providers, sorted by timestamp ascending (None last)."""

    ran: bool = False
    """True if at least one registered clicker-provider analysis is present in the tree."""

    errors: list[str] = field(default_factory=list)
    """Per-source search error messages, so the UI can show 'a search errored' vs 'ran clean'."""


def gather_clicker_results(root: "RootAnalysis") -> ClickerResults:
    """Collect clicker detection state for an alert from all registered providers.

    Returns a :class:`ClickerResults` with events sorted by ``timestamp`` ascending (events lacking
    a timestamp sort to the end), whether any provider analysis ran, and any per-source errors.
    """
    events: list[ClickerEvent] = []
    ran = False
    errors: list[str] = []

    for provider_class in REGISTERED_CLICKER_PROVIDERS:
        for analysis in root.get_analysis_by_type(provider_class):
            # The analysis exists, so detection ran for this observable — record that even if
            # loading its details fails below.
            ran = True

            loader = getattr(analysis, "load_details", None)
            if callable(loader):
                try:
                    loader()
                except Exception:
                    logging.exception(
                        "load_details() failed for clicker event provider %s; skipping",
                        provider_class.__name__,
                    )
                    continue

            error_getter = getattr(analysis, "get_clicker_error", None)
            if callable(error_getter):
                try:
                    error = error_getter()
                except Exception:
                    error = None
                if error:
                    errors.append(error)

            try:
                produced = analysis.get_clicker_events() or []
            except Exception:
                logging.exception(
                    "clicker event provider %s raised; skipping",
                    provider_class.__name__,
                )
                continue

            for event in produced:
                if isinstance(event, ClickerEvent):
                    events.append(event)
                else:
                    logging.warning(
                        "clicker event provider %s returned non-ClickerEvent %r; skipping",
                        provider_class.__name__, type(event).__name__,
                    )

    # Sort by click time ascending; events without a timestamp slot to the bottom.
    _MAX = datetime.max.replace(tzinfo=timezone.utc)

    def _sort_key(e: ClickerEvent):
        if e.timestamp is None:
            return (1, _MAX)
        return (0, e.timestamp)

    events.sort(key=_sort_key)
    return ClickerResults(events=events, ran=ran, errors=errors)


def gather_clicker_events(root: "RootAnalysis") -> list[ClickerEvent]:
    """Collect every ClickerEvent for an alert, from all registered providers.

    Returns events sorted by ``timestamp`` ascending; events lacking a timestamp sort
    to the end. Thin wrapper over :func:`gather_clicker_results` for callers that only need events.
    """
    return gather_clicker_results(root).events
