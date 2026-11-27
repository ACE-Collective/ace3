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

The manage page's Remediation filter needs the state of every alert, not of a
page of them, so ``remediation_filter_value()`` at the end of this module is the
same rule again in SQL. A test holds the two copies to agree.
"""
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, NamedTuple, Optional

from sqlalchemy import ColumnElement, Select, and_, case, exists, false, func, literal, not_, or_, select, true
from sqlalchemy.orm import aliased

from saq.constants import F_EMAIL_DELIVERY, parse_email_delivery
from saq.database.model import (
    ExternalRemediationCheck,
    Observable,
    ObservableMapping,
    ObservableRemediationMapping,
    ObservableTagIndex,
    Remediation,
    Tag,
)
from saq.database.pool import get_db
from saq.email import describe_undelivered
from saq.modules.email.constants import DELIVERY_EXPANDED, DELIVERY_NOT_JOURNALED, DELIVERY_TAG_REASONS
from saq.remediation.external.database import superseding_source_from_reason
from saq.remediation.external.events import events_from_check
from saq.remediation.external.types import CheckResult, CheckStatus
from saq.remediation.types import REMEDIATION_SOURCE_ANY, RemediationAction, RemediationStatus, RemediatorStatus

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

    pending_checks: list = field(default_factory=list)
    """The ``ExternalRemediationCheck`` rows still being polled for this target."""

    pending_remediation: Optional[Remediation] = None
    """ACE's latest ``Remediation`` of this target, while it has not completed."""

    undelivered: Optional[str] = None
    """Why the journal shows this address did not receive its own copy (a ``DELIVERY_*``
    reason), from the delivery tag EmailAnalyzer put on the observable."""

    not_delivered: bool = False
    """The journal explains ACE's finished, unsuccessful removal: there was nothing to remove
    at this address. Such a target is left out of the alert's counts."""

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
        if self.not_delivered:
            return describe_undelivered(self.undelivered)
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
    def counted(self) -> list[TargetCoverage]:
        """The targets the counts and the state cover: all but those the journal shows had
        nothing to remove."""
        return [t for t in self.targets if not t.not_delivered]

    @property
    def total(self) -> int:
        return len(self.counted)

    @property
    def remediated_count(self) -> int:
        return sum(1 for t in self.counted if t.remediated)

    @property
    def sources(self) -> list[str]:
        """Sorted, de-duplicated source labels across every target."""
        return sorted({source for t in self.targets for source in t.sources})

    @property
    def not_found_count(self) -> int:
        return sum(1 for t in self.counted if t.not_found and not t.remediated)

    @property
    def covered_count(self) -> int:
        """Targets nothing is left to do for: remediated, or not in the mailbox."""
        return sum(1 for t in self.counted if t.remediated or t.not_found)

    @property
    def state(self) -> CoverageState:
        if not self.counted or not any(t.attempted for t in self.counted):
            return CoverageState.NONE
        if any(t.failed and not t.remediated for t in self.counted):
            return CoverageState.FAILED
        covered = self.covered_count
        if covered and not self.remediated_count:
            # only "not in mailbox" so far: nothing to act on, but nothing to credit either
            return CoverageState.NOT_FOUND
        if covered == self.total:
            return CoverageState.REMEDIATED
        if covered > 0:
            return CoverageState.PARTIAL
        if any(t.pending for t in self.counted):
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
    def _removal_in_flight(self) -> bool:
        """ACE is still removing one of the targets; this splits PENDING into "remediating" and
        "watching". Over every target, not only the counted ones."""
        return any(t.remediating for t in self.targets)

    @property
    def filter_value(self) -> str:
        """This alert's value of the manage page's Remediation filter, a key of
        ``ALERT_REMEDIATION_FILTER_OPTIONS``. ``remediation_filter_value()`` is the same rule in SQL."""
        if self.state is CoverageState.PENDING:
            return "remediating" if self._removal_in_flight else "watching"
        return {
            CoverageState.NONE: "none",
            CoverageState.UNREMEDIATED: "not_remediated",
            CoverageState.NOT_FOUND: "not_in_mailbox",
            CoverageState.PARTIAL: "partial",
            CoverageState.REMEDIATED: "remediated",
            CoverageState.FAILED: "failed",
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
            CoverageState.PENDING: "remediating" if self._removal_in_flight else "watching",
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
        remaining = len(self.targets) - TOOLTIP_TARGET_LIMIT
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

    # 4. the delivery tags on those observables, which are scoped to the alert: the journal
    #    of this alert's email says where that address's copy went
    undelivered_by_alert: dict[str, dict[str, str]] = defaultdict(dict)
    if value_by_observable_id:
        tag_rows = (
            db.query(ObservableTagIndex.alert_id, ObservableTagIndex.observable_id, Tag.name)
            .join(Tag, Tag.id == ObservableTagIndex.tag_id)
            .filter(ObservableTagIndex.alert_id.in_(alert_ids))
            .filter(ObservableTagIndex.observable_id.in_(list(value_by_observable_id)))
            .filter(Tag.name.in_(list(DELIVERY_TAG_REASONS)))
            .all()
        )
        for alert_id, observable_id, tag_name in tag_rows:
            reason = DELIVERY_TAG_REASONS.get(tag_name.lower())
            if reason:
                undelivered_by_alert[uuid_by_id[alert_id]][value_by_observable_id[observable_id]] = reason

    return assemble_coverage(alert_uuids, targets_by_alert, ace_rows_by_target, checks_by_alert, undelivered_by_alert)


def journal_explains(reason: Optional[str], result: Optional[str]) -> bool:
    """Whether the journal's account of an address explains ACE's finished removal there
    finding nothing to remove.

    - expanded: a distribution list holds no mail, so any unsuccessful result is expected.
    - forwarded: NOT_FOUND or FAILED (the address is not a mailbox) is expected. ERROR is not:
      it says nothing about the address, and a mailbox that keeps a copy and forwards can have
      its own Recipient: line in another journal report.
    - not_journaled: only NOT_FOUND, for the same reason: another report may name the address.
    """
    if reason is None:
        return False
    explained = {RemediatorStatus.NOT_FOUND.value}
    if reason != DELIVERY_NOT_JOURNALED:
        explained.add(RemediatorStatus.FAILED.value)
    if reason == DELIVERY_EXPANDED:
        explained.add(RemediatorStatus.ERROR.value)
    return result in explained


def assemble_coverage(
    alert_uuids: Iterable[str],
    targets_by_alert: dict[str, set[str]],
    ace_rows_by_target: dict[str, list],
    checks_by_alert: dict[str, list],
    undelivered_by_alert: Optional[dict[str, dict[str, str]]] = None,
) -> dict[str, RemediationCoverage]:
    """Pure aggregation over already-fetched rows. See ``get_remediation_coverage``.

    ``ace_rows_by_target`` lists each target's ``Remediation`` rows in ascending
    id order; only the latest row decides that target's ACE state.
    ``checks_by_alert`` lists ``ExternalRemediationCheck`` rows per alert.
    ``undelivered_by_alert`` maps each alert's targets to the journal reason of
    its delivery tag, for the targets that have one.
    """
    undelivered_by_alert = undelivered_by_alert or {}
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

        undelivered = undelivered_by_alert.get(alert_uuid, {})
        for value, target in targets.items():
            rows = ace_rows_by_target.get(value, ())
            _apply_ace_rows(target, rows)
            target.undelivered = undelivered.get(value)
            latest = rows[-1] if rows else None
            if (latest is not None and not target.remediated and not target.pending
                    and latest.action == RemediationAction.REMOVE.value
                    and journal_explains(target.undelivered, latest.result)):
                target.not_delivered = True
                target.failed = False

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
        target.pending_remediation = latest
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
        target.pending_checks.append(check)
        return

    if check.result == CheckResult.CONFIRMED.value:
        sources = {event.source for event in events_from_check(check) if event.source}
        target.sources.update(sources or {check.probe_name})


# --- the same rule in SQL, for the manage page's Remediation filter ---
#
# The filter runs over every alert the rest of the filter list leaves in play, so it cannot load
# rows and call assemble_coverage() the way a page of alerts does. This is the rule above again as
# one SQL expression per alert. test_the_filter_agrees_with_the_column in
# tests/saq/remediation/test_coverage.py runs every coverage scenario through both copies, so a
# change to one without the other fails there.
#
# One difference from assemble_coverage() as the manage page calls it: a probe's target the alert
# does not map never takes ACE's remediation rows. assemble_coverage() gives it the rows of any
# alert on the same page that maps the value, which a query of one alert cannot see.
#
# The filter can also name a source: one remediator or one probe. The state is then the same rule
# over that source's rows alone (remediation.name, external_remediation_check.probe_name); the
# alert's email targets, and the journal's delivery tags on them, are the same for every source.


class _TargetFlags(NamedTuple):
    """The TargetCoverage flags of one kind of target, as SQL booleans over its rows. Each one
    must be strictly true or false, never NULL: the CASE negates them."""
    counted: ColumnElement[bool]
    attempted: ColumnElement[bool]
    failed: ColumnElement[bool]
    remediating: ColumnElement[bool]
    pending: ColumnElement[bool]
    remediated: ColumnElement[bool]
    covered: ColumnElement[bool]


class _Targets(NamedTuple):
    """One kind of target of an alert: a select of one row per target, correlated to the alert,
    and the flags over those rows."""
    rows: Select
    flags: _TargetFlags


def _value_key(value) -> ColumnElement[bytes]:
    """The observables.sha256 of the email_delivery with this value: the sha256 of its UTF-8
    bytes (Observable.sha256_bytes). Matching on it is byte-exact like assemble_coverage()'s
    string keys, and uses i_type_sha256."""
    return func.unhex(func.sha2(value, 256))


def _check_pending(check) -> ColumnElement[bool]:
    return check.status != CheckStatus.COMPLETED.value


def _check_confirmed(check) -> ColumnElement[bool]:
    return and_(check.status == CheckStatus.COMPLETED.value, check.result == CheckResult.CONFIRMED.value)


def _check_superseded(check) -> ColumnElement[bool]:
    # whatever its status, as assemble_coverage() credits it
    return check.result == CheckResult.SUPERSEDED.value


def _from_probe(check, source: str) -> ColumnElement[bool]:
    return true() if source == REMEDIATION_SOURCE_ANY else check.probe_name == source


def _from_remediator(remediation, source: str) -> ColumnElement[bool]:
    return true() if source == REMEDIATION_SOURCE_ANY else remediation.name == source


def _probe_values(alert, source: str):
    """The source's email_delivery probe rows of the alert, one row per value: its key and whether
    any of its rows is still polling, confirmed or superseded.

    The targets join it on the key, so the alert's probe rows are read and hashed once. Nothing
    indexes the hash, and an EXISTS per target and flag read them all again for every target, which
    made a mass-mailed alert a probe watches cost its recipients squared."""
    check = aliased(ExternalRemediationCheck)
    value_key = _value_key(check.observable_value)

    def any_row(condition: ColumnElement[bool]) -> ColumnElement[int]:
        return func.max(case((condition, 1), else_=0))

    return (
        select(value_key.label("value_key"),
               any_row(_check_pending(check)).label("pending"),
               any_row(_check_confirmed(check)).label("confirmed"),
               any_row(_check_superseded(check)).label("superseded"))
        .where(check.alert_uuid == alert.uuid, check.observable_type == F_EMAIL_DELIVERY,
               _from_probe(check, source))
        .group_by(value_key)
        # two levels below the query that selects the alert, which SQLAlchemy does not look through
        # on its own: left to itself it selects from `alerts` and reads every alert's probe rows
        .correlate(alert)
        .lateral()
    )


def _mapped_targets(alert, source: str) -> _Targets:
    """The email_delivery observables mapped to the alert, each joined to the source's latest
    remediation of it (the only one that decides its ACE state, see _apply_ace_rows)."""
    mapping = aliased(ObservableMapping)
    observable = aliased(Observable)
    remediation_mapping = aliased(ObservableRemediationMapping)
    remediation = aliased(Remediation)

    latest_mapping = aliased(ObservableRemediationMapping)
    latest = aliased(Remediation)
    latest_id = (
        select(func.max(latest.id))
        .select_from(latest_mapping)
        .join(latest, latest.id == latest_mapping.remediation_id)
        .where(latest_mapping.observable_id == observable.id, latest.type == F_EMAIL_DELIVERY,
               _from_remediator(latest, source))
        .correlate(observable)
        .scalar_subquery()
    )
    probes = _probe_values(alert, source)
    # through the mapping row of the latest remediation (a primary key lookup), so the join
    # names the observable it belongs to
    rows = (
        select(literal(1))
        .select_from(mapping)
        .join(observable, and_(observable.id == mapping.observable_id, observable.type == F_EMAIL_DELIVERY))
        .outerjoin(remediation_mapping, and_(remediation_mapping.observable_id == observable.id,
                                             remediation_mapping.remediation_id == latest_id))
        .outerjoin(remediation, remediation.id == remediation_mapping.remediation_id)
        .outerjoin(probes, probes.c.value_key == observable.sha256)
        .where(mapping.alert_id == alert.id)
    )

    # remediation.status and .action are NOT NULL, so these are only NULL-free behind `ace`
    ace = remediation.id.is_not(None)
    ace_pending = and_(ace, remediation.status != RemediationStatus.COMPLETED.value)
    removed = and_(ace, remediation.status == RemediationStatus.COMPLETED.value,
                   remediation.action == RemediationAction.REMOVE.value)

    def removal_result(*statuses: RemediatorStatus) -> ColumnElement[bool]:
        return and_(removed, remediation.result.is_not(None),
                    remediation.result.in_([status.value for status in statuses]))

    success = removal_result(RemediatorStatus.SUCCESS)
    not_found = removal_result(RemediatorStatus.NOT_FOUND)
    # the probe columns are only NULL-free behind `probed`, as the remediation's are behind `ace`
    probed = probes.c.value_key.is_not(None)
    confirmed = and_(probed, probes.c.confirmed == 1)
    superseded = and_(probed, probes.c.superseded == 1)
    pending = or_(ace_pending, and_(probed, probes.c.pending == 1))

    # the journal explains the finished removal finding nothing (journal_explains): one
    # (tag, result) pair per combination it accepts, so the rule is not written out twice
    tag_index = aliased(ObservableTagIndex)
    tag = aliased(Tag)
    explained_pairs = [
        and_(tag.name == tag_name, remediation.result == status.value)
        for tag_name, reason in DELIVERY_TAG_REASONS.items()
        for status in RemediatorStatus
        if journal_explains(reason, status.value)
    ]
    explained = and_(removed, remediation.result.is_not(None), exists().where(
        tag_index.alert_id == alert.id,
        tag_index.observable_id == observable.id,
        tag.id == tag_index.tag_id,
        or_(*explained_pairs),
    ).correlate_except(tag_index, tag))
    # SUPERSEDED is left out on purpose: assemble_coverage() credits it after deciding this
    not_delivered = and_(explained, not_(or_(success, confirmed)), not_(pending))

    return _Targets(rows, _TargetFlags(
        counted=not_(not_delivered),
        attempted=or_(ace, probed),
        failed=removal_result(RemediatorStatus.FAILED, RemediatorStatus.ERROR),
        remediating=and_(ace_pending, remediation.action == RemediationAction.REMOVE.value),
        pending=pending,
        remediated=or_(success, confirmed, superseded),
        covered=or_(success, confirmed, superseded, not_found),
    ))


def _check_only_targets(alert, source: str) -> _Targets:
    """The values the source's email_delivery probe rows of the alert name that the alert does not
    map: each is a target of its own (assemble_coverage()), with no ACE rows or tags."""
    probes = _probe_values(alert, source)
    mapping = aliased(ObservableMapping)
    observable = aliased(Observable)
    mapped = exists().where(
        mapping.alert_id == alert.id,
        observable.id == mapping.observable_id,
        observable.type == F_EMAIL_DELIVERY,
        observable.sha256 == probes.c.value_key,
    ).correlate_except(mapping, observable)
    rows = select(literal(1)).select_from(probes).where(not_(mapped))

    remediated = or_(probes.c.confirmed == 1, probes.c.superseded == 1)
    return _Targets(rows, _TargetFlags(
        counted=true(),
        attempted=true(),
        failed=false(),
        remediating=false(),
        pending=probes.c.pending == 1,
        remediated=remediated,
        covered=remediated,
    ))


def has_remediation_activity(alert, source: str = REMEDIATION_SOURCE_ANY) -> ColumnElement[bool]:
    """Whether the source (any remediator or probe by default) has a remediation row for an
    observable the alert maps, or a probe row for the alert: a superset of the alerts whose filter
    value for that source is anything but "none".

    The two subqueries are not correlated, so MySQL materializes each once per statement and
    probes it per alert. The filter's CASE walks every observable an alert maps, and most alerts
    have no remediation at all; this answers "none" for those without the walk (3.4 s down to
    a fraction of a second over 100k alerts with 30 observables each)."""
    mapping = aliased(ObservableMapping)
    remediation_mapping = aliased(ObservableRemediationMapping)
    remediation = aliased(Remediation)
    check = aliased(ExternalRemediationCheck)
    remediated = (
        select(mapping.alert_id)
        .join(remediation_mapping, remediation_mapping.observable_id == mapping.observable_id)
        .join(remediation, and_(remediation.id == remediation_mapping.remediation_id,
                                remediation.type == F_EMAIL_DELIVERY, _from_remediator(remediation, source)))
        .correlate(None)
    )
    probed = (
        select(check.alert_uuid)
        .where(check.observable_type == F_EMAIL_DELIVERY, _from_probe(check, source))
        .correlate(None)
    )
    return or_(alert.id.in_(remediated), alert.uuid.in_(probed))


def remediation_filter_value(alert, source: str = REMEDIATION_SOURCE_ANY) -> ColumnElement[str]:
    """The alert's state for the manage page's Remediation filter (``RemediationCoverage.filter_value``
    as SQL) over the source's rows, correlated to ``alert``, the entity or alias the outer query
    selects. Never NULL, so ``NOT IN`` is the exact complement of ``IN``."""
    mapped = _mapped_targets(alert, source)
    check_only = _check_only_targets(alert, source)

    def any_target(predicate: Callable[[_TargetFlags], ColumnElement[bool]]) -> ColumnElement[bool]:
        # Over the mapped targets an aggregate of the select the CASE runs in, so the alert's
        # observable_mapping rows are walked once rather than once per predicate; COALESCE because
        # an alert with no email maps no rows, and MAX of nothing is NULL.
        mapped_any = func.coalesce(func.max(case((predicate(mapped.flags), 1), else_=0)), 0) == 1
        return or_(mapped_any, check_only.rows.where(predicate(check_only.flags)).correlate(alert).exists())

    # in the order RemediationCoverage.state decides, PENDING split as filter_value splits it
    state = case(
        (not_(any_target(lambda t: and_(t.counted, t.attempted))), "none"),
        (any_target(lambda t: and_(t.counted, t.failed, not_(t.remediated))), "failed"),
        (and_(any_target(lambda t: and_(t.counted, t.covered)),
              not_(any_target(lambda t: and_(t.counted, t.remediated)))), "not_in_mailbox"),
        (not_(any_target(lambda t: and_(t.counted, not_(t.covered)))), "remediated"),
        (any_target(lambda t: and_(t.counted, t.covered)), "partial"),
        # a removal in flight is pending and counted
        (any_target(lambda t: t.remediating), "remediating"),
        (any_target(lambda t: and_(t.counted, t.pending)), "watching"),
        else_="not_remediated",
    )
    # an aggregate without GROUP BY, so exactly one row per alert, email or not
    per_alert = mapped.rows.with_only_columns(state).correlate(alert).scalar_subquery()
    return case((not_(has_remediation_activity(alert, source)), "none"), else_=per_alert)
