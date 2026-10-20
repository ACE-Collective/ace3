"""The SQL of the SVS runs screen's filters (saq.gui.filter_screens.SVS_RUNS_SCREEN).

Each entry becomes one condition on svs_runs: the values of an entry are ORed, the entries are ANDed
(repeats of one filter are merged first), and an inverted entry matches exactly the rows the entry
does not, including rows whose value is NULL. Every condition stands on its own (the catalog, the
targets and the users are subqueries), so the event feed applies the same filters to an event's run.
"""

from datetime import tzinfo

import pytz
from sqlalchemy import and_, case, exists, false, literal, or_, select, true
from sqlalchemy.sql.elements import ColumnElement

from saq.constants import DISPOSITION_OPEN
from saq.database.model import Alert, SVSAttribution, SVSCatalogTest, SVSRun, SVSRunResult, SVSRunTarget, User
from saq.svs.catalog_filters import technique_condition
from saq.svs.constants import AttributionConfidence, ResultStatus, RunState
from saq.svs.filters import date_range_condition
from saq.svs.hosts import InvalidTestHost, split_hostname


# a run in these states is done with: nothing more happens to it unless a person acts
TERMINAL_STATES = (RunState.REVIEWED.value, RunState.CLOSED.value)


def open_alerts_condition() -> ColumnElement[bool]:
    """The run has an alert attributed to it that is still open."""
    return SVSRun.id.in_(
        select(SVSAttribution.run_id)
        .join(Alert, Alert.uuid == SVSAttribution.alert_uuid)
        .where(SVSAttribution.removed_at.is_(None), Alert.disposition == DISPOSITION_OPEN))


def _result_condition(*statuses: ResultStatus) -> ColumnElement[bool]:
    """The run's live result has a signature in one of the statuses."""
    return exists(select(literal(1)).where(
        SVSRunResult.run_id == SVSRun.id, SVSRunResult.status.in_([status.value for status in statuses])))


def _attribution_condition(*conditions) -> ColumnElement[bool]:
    """An attribution to the run that holds matches the conditions."""
    return exists(select(literal(1)).where(
        SVSAttribution.run_id == SVSRun.id, SVSAttribution.removed_at.is_(None), *conditions))


def needs_attention_condition() -> ColumnElement[bool]:
    """The runs a person has to look at: ended and not reviewed, failed, changed since they were
    reviewed, or reviewed or closed with an alert still open (one an analyst took, a partial one, or
    one closing could not reach). This is the one definition of the Needs Attention view and its
    count."""
    return or_(
        SVSRun.state == RunState.ENDED.value,
        SVSRun.state == RunState.ERROR.value,
        and_(SVSRun.state == RunState.REVIEWED.value, SVSRun.changed_since_review.is_(True)),
        and_(SVSRun.state.in_(TERMINAL_STATES), open_alerts_condition()))


def _flag(condition: ColumnElement[bool], values: list[str]) -> ColumnElement[bool]:
    if values == ["true"]:
        return condition
    if values == ["false"]:
        return case((condition, false()), else_=true())
    return true()


def _catalog(condition: ColumnElement[bool]) -> ColumnElement[bool]:
    return SVSRun.test_guid.in_(select(SVSCatalogTest.guid).where(condition))


def _user(column, values: list[str]) -> ColumnElement[bool]:
    return column.in_(select(User.id).where(User.username.in_(values)))


def _target(values: list[str]) -> ColumnElement[bool]:
    hosts = []
    for value in values:
        try:
            hosts.append(split_hostname(value)[0])
        except InvalidTestHost:
            continue

    if not hosts:
        return false()

    return exists(select(literal(1)).where(SVSRunTarget.run_id == SVSRun.id, SVSRunTarget.host.in_(hosts)))


def run_filter_condition(entry: dict, tz: tzinfo = pytz.utc) -> ColumnElement[bool]:
    """The condition of one validated filter entry ({name, inverted, values})."""
    name, values = entry["name"], entry["values"]
    if name == "State":
        condition = SVSRun.state.in_(values)
    elif name == "Test":
        condition = SVSRun.test_guid.in_(values)
    elif name == "Test Name":
        condition = _catalog(or_(*[SVSCatalogTest.name.contains(value, autoescape=True) for value in values]))
    elif name == "Technique":
        condition = _catalog(or_(*[technique_condition(SVSCatalogTest.technique, value) for value in values]))
    elif name == "Target":
        condition = _target(values)
    elif name == "Platform":
        condition = SVSRun.platform.in_(values)
    elif name == "Launcher":
        condition = or_(*[SVSRun.launcher.contains(value, autoescape=True) for value in values])
    elif name == "Batch":
        condition = SVSRun.batch_id.in_(values)
    elif name == "Created":
        condition = date_range_condition(SVSRun.created_at, values, tz)
    elif name == "Started":
        condition = date_range_condition(SVSRun.started_at, values, tz)
    elif name == "Ended":
        condition = date_range_condition(SVSRun.ended_at, values, tz)
    elif name == "Reviewed":
        condition = date_range_condition(SVSRun.reviewed_at, values, tz)
    elif name == "Owner":
        condition = _user(SVSRun.owner_id, values)
    elif name == "Reviewer":
        condition = _user(SVSRun.reviewer_id, values)
    elif name == "Reason":
        condition = or_(*[or_(SVSRun.close_reason.contains(value, autoescape=True),
                              SVSRun.error_reason.contains(value, autoescape=True)) for value in values])
    elif name == "Changed Since Review":
        condition = _flag(SVSRun.changed_since_review.is_(True), values)
    elif name == "Has Open Alerts":
        condition = _flag(open_alerts_condition(), values)
    elif name == "Needs Attention":
        condition = _flag(needs_attention_condition(), values)
    elif name == "Has Missing":
        condition = _flag(_result_condition(ResultStatus.MISSING, ResultStatus.POSSIBLY_SUPPRESSED), values)
    elif name == "Has Possibly Suppressed":
        condition = _flag(_result_condition(ResultStatus.POSSIBLY_SUPPRESSED), values)
    elif name == "Has Candidates":
        condition = _flag(_result_condition(ResultStatus.CANDIDATE), values)
    elif name == "Has Late":
        condition = _flag(_attribution_condition(SVSAttribution.late.is_(True)), values)
    elif name == "Has Context Only":
        condition = _flag(_attribution_condition(
            SVSAttribution.confidence == AttributionConfidence.CONTEXT.value), values)
    else:
        raise ValueError(f"unknown runs filter {name!r}")

    if not entry.get("inverted"):
        return condition

    # a CASE keeps the rows whose value is NULL in the inverse
    return case((condition, false()), else_=true())


def run_filter_conditions(entries: list[dict], tz: tzinfo = pytz.utc) -> list[ColumnElement[bool]]:
    """The conditions of a filter list, to be ANDed; repeats of one filter with the same polarity are
    merged into one entry first."""
    merged: dict[tuple[str, bool], list[str]] = {}
    for entry in entries:
        merged.setdefault((entry["name"], bool(entry.get("inverted"))), []).extend(entry["values"])

    return [run_filter_condition({"name": name, "inverted": inverted, "values": values}, tz)
            for (name, inverted), values in merged.items()]
