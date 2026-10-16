"""Atomic Red Team test catalog service for ACE API v2 (docs/SVS_RUNS.md, docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread. saq.svs.catalog writes the
catalog; this reads it, ordered by technique and then name, the Tests screen's default order, with
each test's state and run history (saq.svs.test_state), read for the whole page at once.
"""

import json
from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, and_, or_, select

from aceapi_v2.common.listing import InvalidListingRequest, decode_cursor, encode_cursor, rows_to_csv
from aceapi_v2.svs.catalog.schemas import CATALOG_TEST_CSV_FIELDS, CatalogTest, CatalogTestDetail, PlatformState
from saq.database.model import SVSCatalogTest
from saq.database.pool import get_db
from saq.gui.filter_screens import SVS_TESTS_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.svs.catalog import supported_platforms
from saq.svs.catalog_filters import catalog_filter_conditions
from saq.svs.samples import to_utc_naive
from saq.svs.test_state import TestHistory, catalog_histories
from saq.util.uuid import is_uuid


@dataclass(frozen=True)
class CatalogListing:
    statement: Select


def _filter_entries(filter_params: list[str]) -> list[dict]:
    try:
        entries, _ = decode_filter_query(filter_params, screen=SVS_TESTS_SCREEN, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        return [entry.model_dump() for entry in SVS_TESTS_SCREEN.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))


def prepare_listing(filter_params: list[str], *, changed_since: datetime | None) -> CatalogListing:
    """Builds the listing statement from share-link filters (`f=`) of the tests screen. Raises
    InvalidListingRequest."""
    statement = select(SVSCatalogTest)
    for condition in catalog_filter_conditions(_filter_entries(filter_params)):
        statement = statement.where(condition)

    if changed_since is not None:
        statement = statement.where(SVSCatalogTest.updated_at >= to_utc_naive(changed_since))

    return CatalogListing(statement=statement)


def _row(test: SVSCatalogTest, history: TestHistory) -> dict:
    return dict(
        guid=test.guid, repository=test.repository, technique=test.technique, technique_name=test.technique_name,
        name=test.name, platforms=supported_platforms(test), executor=test.executor, path=test.path,
        commit=test.commit, content_hash=test.content_hash, first_seen_at=test.first_seen_at,
        removed_at=test.removed_at, updated_at=test.updated_at, test_state=history.state.value,
        run_count=history.run_count, last_run_id=history.last_run_uuid, last_run_at=history.last_run_at,
        last_reviewed_run_id=history.last_reviewed_run_uuid, last_reviewed_at=history.last_reviewed_at,
        expected_signatures=history.expected, recent_runs=history.recent_runs,
        recent_runs_missing=history.recent_runs_missing)


def _parse_key(payload: dict) -> tuple[str, str, int]:
    technique, name, row_id = payload["k"]
    return str(technique), str(name), int(row_id)


def fetch_page(listing: CatalogListing, cursor: str | None, limit: int) -> tuple[list[CatalogTest], str | None]:
    """One page of the listing in (technique, name) order after `cursor`, and the next page's
    cursor. Raises InvalidCursor."""
    statement = listing.statement
    if cursor is not None:
        technique, name, row_id = decode_cursor(cursor, _parse_key)
        statement = statement.where(or_(
            SVSCatalogTest.technique > technique,
            and_(SVSCatalogTest.technique == technique, SVSCatalogTest.name > name),
            and_(SVSCatalogTest.technique == technique, SVSCatalogTest.name == name, SVSCatalogTest.id > row_id)))

    rows = get_db().execute(statement.order_by(
        SVSCatalogTest.technique, SVSCatalogTest.name, SVSCatalogTest.id).limit(limit + 1)).scalars().all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = encode_cursor(k=[last.technique, last.name, last.id])

    histories = catalog_histories(get_db(), rows)
    return [CatalogTest(**_row(test, histories[test.guid])) for test in rows], next_cursor


def catalog_tests_to_csv(rows: list[CatalogTest], *, header: bool) -> str:
    def flatten(values: dict) -> None:
        values["platforms"] = ",".join(values["platforms"])

    return rows_to_csv(rows, CATALOG_TEST_CSV_FIELDS, header=header, flatten=flatten)


def get_catalog_test(guid: str) -> CatalogTestDetail:
    if not is_uuid(guid):
        raise HTTPException(status_code=400, detail=f"invalid test guid {guid!r}")

    test = get_db().query(SVSCatalogTest).filter(SVSCatalogTest.guid == guid.lower()).one_or_none()
    if test is None:
        raise HTTPException(status_code=404, detail=f"test {guid} is not in the catalog")

    history = catalog_histories(get_db(), [test])[test.guid]
    platform_states = [
        PlatformState(platform=platform, test_state=state.state.value, last_reviewed_run_id=state.last_reviewed_run_uuid,
                      last_reviewed_at=state.last_reviewed_at, expected_signatures=state.expected)
        for platform, state in history.platform_states.items()]
    return CatalogTestDetail(**_row(test, history), platform_states=platform_states, description=test.description,
                             test=json.loads(test.test))
