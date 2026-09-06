"""Per-alert remediation coverage for list views.

Answers, for every alert on a page of alerts, "have all the emails in this
alert been remediated, and by what?" using database rows only. The alert list
renders dozens of alerts per page and cannot afford loading each root analysis
from disk the way the alert page's Remediation Timeline does.

Coverage is computed over the alert's ``email_delivery`` targets (one message
delivered to one recipient). A target counts as remediated when any of:

- ACE's own remediation of the target completed successfully -- the latest
  ``remediation`` row for the target is a successful ``remove``. A later
  successful ``restore`` puts the message back and clears it.
- An external remediation probe CONFIRMED the target for this alert
  (``external_remediation_check``).
- A probe row for the target was SUPERSEDED, meaning a sibling probe or ACE
  confirmed the same message first, possibly through a different alert.

An ACE attempt that finds no such message in the mailbox (``NOT_FOUND``) is
neither a remediation nor a failure: something else removed it, or it was never
delivered. Nothing is left to act on, so such a target counts as *covered* for
the alert-level state alongside remediated targets, while its own line reads
"not in mailbox" so ACE never claims credit for it.

The sources reported per target are the same ``RemediationEvent.source``
labels the alert page's Remediation Timeline shows, so the two views agree.
"""
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from saq.constants import F_EMAIL_DELIVERY, parse_email_delivery
from saq.database.model import (
    ExternalRemediationCheck,
    Observable,
    ObservableMapping,
    ObservableRemediationMapping,
    Remediation,
)
from saq.database.pool import get_db
from saq.remediation.external.database import superseding_source_from_reason
from saq.remediation.external.events import events_from_check
from saq.remediation.external.types import CheckResult, CheckStatus
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus

ACE_SOURCE = "ACE"
"""Source label for ACE's own remediations. Matches the timeline's label."""

# Maximum number of per-target lines rendered into the badge tooltip. A
# large mailing-list alert can have hundreds of recipients; the tooltip only
# needs to explain the count, not enumerate the whole list.
TOOLTIP_TARGET_LIMIT = 25


class CoverageState(Enum):
    """Alert-level summary of the per-target states, in badge terms."""
    NONE = "none"                  # no email_delivery targets, or nothing has been attempted
    PENDING = "pending"            # nothing confirmed yet; ACE is still removing it or a probe is still watching
    UNREMEDIATED = "unremediated"  # every attempt finished without confirming anything
    NOT_FOUND = "not_found"        # nothing remediated, but ACE looked and the message is not in the mailbox
    PARTIAL = "partial"            # some targets confirmed, others not
    REMEDIATED = "remediated"      # every target confirmed
    FAILED = "failed"              # an ACE remediation attempt failed on at least one target


@dataclass
class TargetCoverage:
    """Remediation state of one ``email_delivery`` target."""

    target: str
    """The ``email_delivery`` observable value (``<message-id>|recipient``)."""

    sources: set[str] = field(default_factory=set)
    """Display labels of everything that confirmed the target was remediated."""

    failed: bool = False
    """ACE's latest attempt on this target completed unsuccessfully."""

    pending: bool = False
    """An ACE attempt or a probe for this target is still in flight."""

    remediating: bool = False
    """ACE's own removal of this target is still in flight (a subset of ``pending``)."""

    not_found: bool = False
    """ACE's latest attempt found no such message in the mailbox."""

    attempted: bool = False
    """Any remediation or probe row exists for this target at all."""

    @property
    def remediated(self) -> bool:
        return bool(self.sources)

    @property
    def recipient(self) -> str:
        try:
            _, recipient = parse_email_delivery(self.target)
        except ValueError:
            return self.target
        return recipient or self.target

    @property
    def status_display(self) -> str:
        if self.remediated:
            return ", ".join(sorted(self.sources))
        if self.failed:
            return "failed"
        if self.not_found:
            return "not in mailbox"
        if self.remediating:
            return "remediating"
        if self.pending:
            # a probe is still polling the vendor in case it acts later
            return "watching"
        if self.attempted:
            return "not remediated"
        return "not attempted"


@dataclass
class RemediationCoverage:
    """Remediation coverage of one alert across all of its email targets."""

    targets: list[TargetCoverage] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.targets)

    @property
    def remediated_count(self) -> int:
        return sum(1 for t in self.targets if t.remediated)

    @property
    def sources(self) -> list[str]:
        """Sorted, de-duplicated source labels across every target."""
        return sorted({source for t in self.targets for source in t.sources})

    @property
    def not_found_count(self) -> int:
        return sum(1 for t in self.targets if t.not_found and not t.remediated)

    @property
    def covered_count(self) -> int:
        """Targets nothing is left to do for: remediated, or not in the mailbox."""
        return sum(1 for t in self.targets if t.remediated or t.not_found)

    @property
    def state(self) -> CoverageState:
        if not self.targets or not any(t.attempted for t in self.targets):
            return CoverageState.NONE
        if any(t.failed and not t.remediated for t in self.targets):
            return CoverageState.FAILED
        covered = self.covered_count
        if covered and not self.remediated_count:
            # only "not in mailbox" so far: nothing to act on, but nothing to credit either
            return CoverageState.NOT_FOUND
        if covered == self.total:
            return CoverageState.REMEDIATED
        if covered > 0:
            return CoverageState.PARTIAL
        if any(t.pending for t in self.targets):
            return CoverageState.PENDING
        return CoverageState.UNREMEDIATED

    @property
    def visible(self) -> bool:
        """Whether the list view should render a badge for this alert."""
        return self.state is not CoverageState.NONE

    @property
    def css_class(self) -> str:
        return {
            CoverageState.REMEDIATED: "text-bg-success",
            CoverageState.PARTIAL: "text-bg-warning",
            CoverageState.FAILED: "text-bg-danger",
            CoverageState.PENDING: "text-bg-secondary",
            CoverageState.NOT_FOUND: "text-bg-light border border-dark",
            CoverageState.UNREMEDIATED: "text-bg-light border border-dark",
            CoverageState.NONE: "",
        }[self.state]

    @property
    def cell_css_class(self) -> str:
        """Bootstrap contextual class for a table cell dedicated to this state."""
        return {
            CoverageState.REMEDIATED: "table-success",
            CoverageState.PARTIAL: "table-warning",
            CoverageState.FAILED: "table-danger",
            CoverageState.PENDING: "table-secondary",
            CoverageState.NOT_FOUND: "table-light",
            CoverageState.UNREMEDIATED: "",
            CoverageState.NONE: "",
        }[self.state]

    @property
    def status_label(self) -> str:
        """State and counts only, e.g. ``remediated 3/3``."""
        if self.state is CoverageState.NOT_FOUND:
            return f"not in mailbox {self.not_found_count}/{self.total}"
        # remediated and not-in-mailbox targets both count as covered
        counts = f"{self.covered_count}/{self.total}"
        prefix = {
            CoverageState.REMEDIATED: "remediated",
            CoverageState.PARTIAL: "remediated",
            CoverageState.FAILED: "remediation failed",
            # "watching" tells the analyst ACE is still looking for a vendor action,
            # as opposed to "not remediated", which reads as final
            CoverageState.PENDING: "remediating" if any(t.remediating for t in self.targets) else "watching",
            CoverageState.UNREMEDIATED: "not remediated",
            CoverageState.NOT_FOUND: "not in mailbox",
            CoverageState.NONE: "",
        }[self.state]
        return f"{prefix} {counts}"

    @property
    def sources_display(self) -> str:
        return ", ".join(self.sources)

    @property
    def label(self) -> str:
        """Badge text, e.g. ``remediated 3/3 · ACE, Microsoft Defender``."""
        if self.sources:
            return f"{self.status_label} · {self.sources_display}"
        return self.status_label

    @property
    def tooltip(self) -> str:
        """One line per target: ``recipient: <status>``."""
        lines = [f"{t.recipient}: {t.status_display}" for t in self.targets[:TOOLTIP_TARGET_LIMIT]]
        remaining = self.total - TOOLTIP_TARGET_LIMIT
        if remaining > 0:
            lines.append(f"... and {remaining} more")
        return "\n".join(lines)


def get_remediation_coverage(alerts: Iterable) -> dict[str, RemediationCoverage]:
    """Compute coverage for a page of alerts in three queries.

    ``alerts`` are ``Alert`` ORM objects (or anything with ``id`` and
    ``uuid``). Returns a dict keyed by alert uuid; every alert passed in gets
    an entry, so templates can index it without a guard.
    """
    alerts = list(alerts)
    if not alerts:
        return {}

    alert_ids = [a.id for a in alerts]
    alert_uuids = [a.uuid for a in alerts]
    uuid_by_id = {a.id: a.uuid for a in alerts}
    db = get_db()

    # 1. every email_delivery observable mapped to any alert on the page
    targets_by_alert: dict[str, set[str]] = {uuid: set() for uuid in alert_uuids}
    value_by_observable_id: dict[int, str] = {}
    mapping_rows = (
        db.query(ObservableMapping.alert_id, Observable.id, Observable.value)
        .join(Observable, Observable.id == ObservableMapping.observable_id)
        .filter(ObservableMapping.alert_id.in_(alert_ids))
        .filter(Observable.type == F_EMAIL_DELIVERY)
        .all()
    )
    for alert_id, observable_id, value in mapping_rows:
        target = value.decode("utf8", errors="ignore")
        value_by_observable_id[observable_id] = target
        targets_by_alert[uuid_by_id[alert_id]].add(target)

    # 2. ACE's own remediation rows for those observables. Keyed by target value
    #    because observables are shared across alerts: a message remediated via one
    #    alert is remediated in every alert that contains it.
    ace_rows_by_target: dict[str, list[Remediation]] = defaultdict(list)
    if value_by_observable_id:
        ace_rows = (
            db.query(ObservableRemediationMapping.observable_id, Remediation)
            .join(Remediation, Remediation.id == ObservableRemediationMapping.remediation_id)
            .filter(ObservableRemediationMapping.observable_id.in_(list(value_by_observable_id)))
            .filter(Remediation.type == F_EMAIL_DELIVERY)
            .order_by(Remediation.id.asc())
            .all()
        )
        for observable_id, remediation in ace_rows:
            ace_rows_by_target[value_by_observable_id[observable_id]].append(remediation)

    # 3. external probe rows, which are scoped to the alert
    checks_by_alert: dict[str, list[ExternalRemediationCheck]] = defaultdict(list)
    check_rows = (
        db.query(ExternalRemediationCheck)
        .filter(ExternalRemediationCheck.alert_uuid.in_(alert_uuids))
        .filter(ExternalRemediationCheck.observable_type == F_EMAIL_DELIVERY)
        .order_by(ExternalRemediationCheck.id.asc())
        .all()
    )
    for check in check_rows:
        checks_by_alert[check.alert_uuid].append(check)

    return assemble_coverage(alert_uuids, targets_by_alert, ace_rows_by_target, checks_by_alert)


def assemble_coverage(
    alert_uuids: Iterable[str],
    targets_by_alert: dict[str, set[str]],
    ace_rows_by_target: dict[str, list],
    checks_by_alert: dict[str, list],
) -> dict[str, RemediationCoverage]:
    """Pure aggregation over already-fetched rows. See ``get_remediation_coverage``.

    ``ace_rows_by_target`` lists each target's ``Remediation`` rows in ascending
    id order; only the latest row decides that target's ACE state.
    ``checks_by_alert`` lists ``ExternalRemediationCheck`` rows per alert.
    """
    result: dict[str, RemediationCoverage] = {}
    for alert_uuid in alert_uuids:
        targets: dict[str, TargetCoverage] = {}
        for value in sorted(targets_by_alert.get(alert_uuid, ())):
            targets[value] = TargetCoverage(target=value)

        # A probe row whose target was never mapped to the alert still describes
        # one of the alert's emails, so it contributes a target of its own.
        checks = checks_by_alert.get(alert_uuid, ())
        for check in checks:
            target = targets.setdefault(check.observable_value, TargetCoverage(target=check.observable_value))
            _apply_check(target, check)

        for value, target in targets.items():
            _apply_ace_rows(target, ace_rows_by_target.get(value, ()))

        # A SUPERSEDED row only says "someone else confirmed this first". When that
        # someone is visible here (the sibling's CONFIRMED row, or ACE's own row)
        # its display label is already on the target; the probe name recovered
        # from the supersede reason is the fallback for a confirmation that lives
        # on another alert.
        for check in checks:
            if check.result != CheckResult.SUPERSEDED.value:
                continue
            target = targets[check.observable_value]
            if not target.remediated:
                target.sources.add(superseding_source_from_reason(check.result_message) or "superseded")

        result[alert_uuid] = RemediationCoverage(targets=list(targets.values()))
    return result


def _apply_ace_rows(target: TargetCoverage, rows: Iterable) -> None:
    latest: Optional[Remediation] = None
    for row in rows:
        latest = row
    if latest is None:
        return

    target.attempted = True
    if latest.status != RemediationStatus.COMPLETED.value:
        target.pending = True
        target.remediating = latest.action == RemediationAction.REMOVE.value
        return

    if latest.action != RemediationAction.REMOVE.value:
        # a completed restore (or anything that is not a removal) leaves the
        # message in the mailbox, whatever happened before it
        return

    if latest.result == RemediatorStatus.SUCCESS.value:
        target.sources.add(ACE_SOURCE)
    elif latest.result == RemediatorStatus.NOT_FOUND.value:
        target.not_found = True
    elif latest.result in (RemediatorStatus.FAILED.value, RemediatorStatus.ERROR.value):
        target.failed = True


def _apply_check(target: TargetCoverage, check) -> None:
    target.attempted = True
    if check.status != CheckStatus.COMPLETED.value:
        target.pending = True
        return

    if check.result == CheckResult.CONFIRMED.value:
        sources = {event.source for event in events_from_check(check) if event.source}
        target.sources.update(sources or {check.probe_name})
