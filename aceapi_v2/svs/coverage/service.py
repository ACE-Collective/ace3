"""ATT&CK coverage service for ACE API v2 (docs/SVS_COVERAGE.md, docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread. saq.svs.coverage writes
svs_coverage and svs_coverage_snapshots; this reads them. The lists page by keyset over (technique,
platform, id), or (snapshot_date, technique, platform, id) for the history, and over (updated_at, id)
for a changed_since pull. A technique's drill-down reads its rows as of the last refresh and
evaluates its tests now (saq.svs.coverage.technique_detail).
"""

import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import Callable

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, and_, func, or_, select

from aceapi_v2.common.listing import (
    CHANGED_SINCE_SETTLE_SECONDS,
    InvalidCursor,
    InvalidListingRequest,
    decode_cursor,
    encode_cursor,
    rows_to_csv,
    settled,
)
from aceapi_v2.svs.coverage.schemas import (
    COVERAGE_CSV_FIELDS,
    COVERAGE_HISTORY_CSV_FIELDS,
    CoverageHistoryCounts,
    CoverageRow,
    CoverageSnapshotRow,
    CoverageSummary,
    CoverageTest,
    ManualSignature,
    MeasuredSignature,
    PeriodCounts,
    PlatformCounts,
    RemovedTest,
    TechniqueCoverage,
    TestPlatform,
)
from saq.database.model import SVSCoverage, SVSCoverageSnapshot, SVSCoverageState
from saq.database.pool import get_db
from saq.gui.filter_screens import SVS_COVERAGE_HISTORY_SCREEN, SVS_COVERAGE_SCREEN, FilterScreen
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.svs.attack import get_attack_catalog
from saq.svs.constants import CoverageState
from saq.svs.coverage import STATE_ID, technique_detail
from saq.svs.coverage_filters import coverage_filter_conditions, history_filter_conditions
from saq.svs.samples import to_utc_naive
from saq.svs.signatures import describe_signatures
from saq.svs.test_state import TestState

STATES = tuple(state.value for state in CoverageState)

# the listing orders: the screen's, or (updated_at, id) for a changed_since pull
LISTING_ORDER_TECHNIQUE = "technique"
LISTING_ORDER_DATE = "date"
LISTING_ORDER_UPDATED = "updated_at"

GROUP_DAY = "day"
GROUP_MONTH = "month"


def _filter_entries(screen: FilterScreen, filter_params: list[str]) -> list[dict]:
    try:
        entries, _ = decode_filter_query(filter_params, screen=screen, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        return [entry.model_dump() for entry in screen.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))


def _counts(rows) -> dict[str, int]:
    """Every state, counted from (state, count) rows."""
    counts = dict.fromkeys(STATES, 0)
    for state, count in rows:
        counts[state] += count
    return counts


#
# keyset paging over a list of columns
#

def _after(columns, values) -> object:
    """Rows strictly after values in the order of columns (all ascending)."""
    conditions = []
    for index, column in enumerate(columns):
        conditions.append(and_(*[columns[i] == values[i] for i in range(index)], column > values[index]))
    return or_(*conditions)


def _page(statement: Select, table, order: str, order_columns: dict[str, tuple[str, ...]],
          parse_value: dict[str, Callable], cursor: str | None, limit: int) -> tuple[list, str | None]:
    """One page of statement in the order named, and the next page's cursor."""
    names = order_columns[order]
    columns = [getattr(table, name) for name in names]

    def parse(payload: dict) -> list:
        if payload["o"] != order:
            raise InvalidCursor(
                f"this cursor pages a listing ordered by {payload['o']}, not {order}: "
                "pass the same changed_since (or none) as the request that returned it")
        values = payload["k"]
        if len(values) != len(names):
            raise InvalidCursor("this cursor is for another listing")
        return [parse_value.get(name, lambda value: value)(value) for name, value in zip(names, values)]

    if order == LISTING_ORDER_UPDATED:
        statement = statement.where(settled(table.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
    if cursor is not None:
        statement = statement.where(_after(columns, decode_cursor(cursor, parse)))

    rows = get_db().execute(statement.order_by(*columns).limit(limit + 1)).scalars().all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = encode_cursor(o=order, k=[
            value.isoformat() if isinstance(value, (date, datetime)) else value
            for value in (getattr(last, name) for name in names)])
    return rows, next_cursor


#
# the coverage rows
#

COVERAGE_ORDER_COLUMNS = {
    LISTING_ORDER_TECHNIQUE: ("technique", "platform", "id"),
    LISTING_ORDER_UPDATED: ("updated_at", "id"),
}
COVERAGE_CURSOR_VALUES = {"updated_at": datetime.fromisoformat, "id": int, "technique": str, "platform": str}


@dataclass(frozen=True)
class CoverageListing:
    statement: Select
    order: str


def prepare_listing(filter_params: list[str], *, changed_since: datetime | None, tz) -> CoverageListing:
    """Builds the listing statement from share-link filters (`f=`) of the coverage screen. Raises
    InvalidListingRequest."""
    statement = select(SVSCoverage).where(
        *coverage_filter_conditions(_filter_entries(SVS_COVERAGE_SCREEN, filter_params), tz))
    if changed_since is None:
        return CoverageListing(statement, LISTING_ORDER_TECHNIQUE)
    return CoverageListing(statement.where(SVSCoverage.updated_at >= to_utc_naive(changed_since)),
                           LISTING_ORDER_UPDATED)


def _coverage_row(row: SVSCoverage) -> CoverageRow:
    return CoverageRow(
        technique=row.technique, platform=row.platform, parent=row.parent, is_subtechnique=row.is_subtechnique,
        technique_name=row.technique_name, tactics=json.loads(row.tactics), catalog_status=row.catalog_status,
        attack_platform=row.attack_platform, state=row.state, own_state=row.own_state, tests_total=row.tests_total,
        tests_validated=row.tests_validated, tests_failing=row.tests_failing, tests_stale=row.tests_stale,
        manual_signatures=row.manual_signatures, measured_signatures=row.measured_signatures,
        last_reviewed_at=row.last_reviewed_at, state_changed_at=row.state_changed_at,
        first_seen_at=row.first_seen_at, retired_at=row.retired_at, updated_at=row.updated_at)


def fetch_page(listing: CoverageListing, cursor: str | None, limit: int) -> tuple[list[CoverageRow], str | None]:
    """One page of the listing after `cursor`, and the next page's cursor (None on the last).
    Raises InvalidCursor."""
    rows, next_cursor = _page(listing.statement, SVSCoverage, listing.order, COVERAGE_ORDER_COLUMNS,
                              COVERAGE_CURSOR_VALUES, cursor, limit)
    return [_coverage_row(row) for row in rows], next_cursor


def coverage_rows_to_csv(rows: list[CoverageRow], *, header: bool) -> str:
    def flatten(values: dict) -> None:
        values["tactics"] = ",".join(values["tactics"])

    return rows_to_csv(rows, COVERAGE_CSV_FIELDS, header=header, flatten=flatten)


def get_summary(filter_params: list[str], tz) -> CoverageSummary:
    """The rows the filters match counted per state and own state, overall and per platform, and
    what the last refresh did. Raises InvalidListingRequest."""
    conditions = coverage_filter_conditions(_filter_entries(SVS_COVERAGE_SCREEN, filter_params), tz)
    db = get_db()
    states: dict[str, list] = {}
    own_states: dict[str, list] = {}
    for column, target in ((SVSCoverage.state, states), (SVSCoverage.own_state, own_states)):
        for platform, state, count in db.execute(
                select(SVSCoverage.platform, column, func.count()).where(*conditions)
                .group_by(SVSCoverage.platform, column)):
            target.setdefault(platform, []).append((state, count))

    # the release's platform order, then any other platform a test brought
    release_order = list(get_attack_catalog().platforms)
    platforms = sorted(states, key=lambda platform: (
        release_order.index(platform) if platform in release_order else len(release_order), platform))
    per_platform = [PlatformCounts(platform=platform, rows=sum(count for _, count in states[platform]),
                                   states=_counts(states[platform]), own_states=_counts(own_states.get(platform, [])))
                    for platform in platforms]

    summary = CoverageSummary(
        rows=sum(counts.rows for counts in per_platform),
        states=_counts((state, count) for rows in states.values() for state, count in rows),
        own_states=_counts((state, count) for rows in own_states.values() for state, count in rows),
        platforms=per_platform)
    refresh = db.get(SVSCoverageState, STATE_ID)
    if refresh is not None:
        summary.attack_release = refresh.attack_release
        summary.refreshed_at = refresh.refreshed_at
        summary.duration_ms = refresh.duration_ms
        summary.unknown_tags = refresh.unknown_tags
        summary.ignored_tags = refresh.ignored_tags
        summary.error = refresh.error
    return summary


#
# a technique's drill-down
#

def get_technique(requested: str) -> TechniqueCoverage:
    catalog = get_attack_catalog()
    try:
        resolution = catalog.resolve(requested)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid technique {requested!r} (expected an ATT&CK id such "
                                                    "as T1059 or T1059.001)")
    technique = resolution.technique

    db = get_db()
    rows = db.execute(select(SVSCoverage).where(or_(SVSCoverage.technique == technique,
                                                    SVSCoverage.parent == technique))
                      .order_by(SVSCoverage.technique, SVSCoverage.platform)).scalars().all()
    own = [row for row in rows if row.technique == technique]
    known = catalog.technique(technique)
    if not own and known is None:
        raise HTTPException(status_code=404, detail=f"no coverage of technique {technique}")

    detail = technique_detail(db, catalog, technique)
    tests = []
    measured: dict[str, list[TestPlatform]] = {}
    for counted in detail.tests:
        evaluation, run = counted.evaluation, counted.evaluation.run if counted.evaluation else None
        expected = sorted(counted.contribution.measured)
        tests.append(CoverageTest(
            guid=counted.test.guid, name=counted.test.name, test_technique=counted.test.technique,
            technique=counted.technique, platform=counted.platform,
            test_state=evaluation.state.value if evaluation is not None else TestState.NEVER_RUN.value,
            contribution=counted.contribution.state.value,
            last_reviewed_run_id=run.uuid if run is not None else None,
            last_reviewed_at=run.reviewed_at if run is not None else None, expected_signatures=expected))
        for signature_uuid in expected:
            measured.setdefault(signature_uuid, []).append(TestPlatform(guid=counted.test.guid,
                                                                        platform=counted.platform))

    described = describe_signatures(measured)
    refresh = db.get(SVSCoverageState, STATE_ID)
    first = own[0] if own else None
    return TechniqueCoverage(
        requested=requested, technique=technique,
        name=known.name if known is not None else (first.technique_name if first else None),
        parent=catalog.parent_of(technique), is_subtechnique="." in technique,
        catalog_status=resolution.status.value,
        tactics=list(known.tactics) if known is not None else [],
        attack_release=catalog.release, refreshed_at=refresh.refreshed_at if refresh is not None else None,
        rows=[_coverage_row(row) for row in own],
        sub_technique_rows=[_coverage_row(row) for row in rows if row.technique != technique],
        tests=tests,
        measured_signatures=[
            MeasuredSignature(signature_uuid=uuid, name=described[uuid].name if uuid in described else None,
                              family=described[uuid].family if uuid in described else None, tests=pairs)
            for uuid, pairs in sorted(measured.items())],
        manual_signatures=[
            ManualSignature(signature_uuid=mapping.signature.uuid, name=mapping.signature.name,
                            family=mapping.signature.family, declared=mapping.declared, technique=mapping.technique,
                            counts=mapping.counts, reason=mapping.reason)
            for mapping in detail.manual],
        manual_signatures_error=detail.manual_error,
        removed_tests=[RemovedTest(guid=test.guid, name=test.name, technique=test.technique,
                                   removed_at=test.removed_at) for test in detail.removed_tests])


#
# the snapshots
#

HISTORY_ORDER_COLUMNS = {
    LISTING_ORDER_DATE: ("snapshot_date", "technique", "platform", "id"),
    LISTING_ORDER_UPDATED: ("updated_at", "id"),
}
HISTORY_CURSOR_VALUES = {"snapshot_date": date.fromisoformat, "updated_at": datetime.fromisoformat, "id": int,
                         "technique": str, "platform": str}


@dataclass(frozen=True)
class HistoryListing:
    statement: Select
    order: str


def prepare_history(filter_params: list[str], *, changed_since: datetime | None, tz) -> HistoryListing:
    """Builds the history statement from share-link filters (`f=`) of the coverage history. Raises
    InvalidListingRequest."""
    statement = select(SVSCoverageSnapshot).where(
        *history_filter_conditions(_filter_entries(SVS_COVERAGE_HISTORY_SCREEN, filter_params), tz))
    if changed_since is None:
        return HistoryListing(statement, LISTING_ORDER_DATE)
    return HistoryListing(statement.where(SVSCoverageSnapshot.updated_at >= to_utc_naive(changed_since)),
                          LISTING_ORDER_UPDATED)


def fetch_history_page(listing: HistoryListing, cursor: str | None,
                       limit: int) -> tuple[list[CoverageSnapshotRow], str | None]:
    """One page of the history after `cursor`, and the next page's cursor. Raises InvalidCursor."""
    rows, next_cursor = _page(listing.statement, SVSCoverageSnapshot, listing.order, HISTORY_ORDER_COLUMNS,
                              HISTORY_CURSOR_VALUES, cursor, limit)
    return [CoverageSnapshotRow.model_validate(row, from_attributes=True) for row in rows], next_cursor


def history_rows_to_csv(rows: list[CoverageSnapshotRow], *, header: bool) -> str:
    return rows_to_csv(rows, COVERAGE_HISTORY_CSV_FIELDS, header=header)


def get_history_counts(filter_params: list[str], group: str, tz) -> CoverageHistoryCounts:
    """The snapshot rows the filters match, counted per state, per day or per month (the month's last
    snapshot). Raises InvalidListingRequest."""
    entries = _filter_entries(SVS_COVERAGE_HISTORY_SCREEN, filter_params)
    db = get_db()
    # the days come from the Date filter alone: a day whose rows the other filters leave out still
    # counts, as zeros, and is still its month's last
    days = db.execute(select(SVSCoverageSnapshot.snapshot_date).distinct().where(
        *history_filter_conditions([entry for entry in entries if entry["name"] == "Date"], tz))
        .order_by(SVSCoverageSnapshot.snapshot_date)).scalars().all()

    periods: dict[str, date] = {}
    for day in days:
        # ascending, so a month keeps its last day
        periods[day.isoformat() if group == GROUP_DAY else day.strftime("%Y-%m")] = day
    if not periods:
        return CoverageHistoryCounts(group=group, data=[])

    conditions = [*history_filter_conditions(entries, tz),
                  SVSCoverageSnapshot.snapshot_date.in_(sorted(set(periods.values())))]
    counted: dict[str, dict[date, list]] = {"state": {}, "own_state": {}}
    for name in counted:
        column = getattr(SVSCoverageSnapshot, name)
        for day, state, count in db.execute(
                select(SVSCoverageSnapshot.snapshot_date, column, func.count()).where(*conditions)
                .group_by(SVSCoverageSnapshot.snapshot_date, column)):
            counted[name].setdefault(day, []).append((state, count))

    return CoverageHistoryCounts(group=group, data=[
        PeriodCounts(period=period, snapshot_date=day,
                     rows=sum(count for _, count in counted["state"].get(day, [])),
                     states=_counts(counted["state"].get(day, [])),
                     own_states=_counts(counted["own_state"].get(day, [])))
        for period, day in periods.items()])
