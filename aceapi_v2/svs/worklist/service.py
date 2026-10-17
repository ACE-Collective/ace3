"""The declared-vs-measured worklist service for ACE API v2 (docs/SVS_COVERAGE.md, *The worklist*;
docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread. saq.svs.worklist derives
svs_technique_worklist on each coverage refresh and writes the resolutions; this reads the rows and
hands it the resolutions people make. The list pages by keyset over (signature_uuid, technique, id),
or over (updated_at, id) for a changed_since pull. A signature's detail adds what it is measured on
now, counted as the refresh counts it (saq.svs.coverage.measured_by_signature).
"""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, select

from aceapi_v2.common.listing import (
    CHANGED_SINCE_SETTLE_SECONDS,
    InvalidListingRequest,
    keyset_page,
    rows_to_csv,
)
from aceapi_v2.svs.expectations.service import require_user
from aceapi_v2.svs.worklist.schemas import (
    WORKLIST_CSV_FIELDS,
    BulkResolutionRequest,
    BulkResolutionResult,
    MeasuredTechnique,
    MeasuredTest,
    ResolutionRequest,
    SignatureWorklist,
    WorklistConflictItem,
    WorklistKey,
    WorklistRow,
)
from saq.database.model import SVSCatalogTest, SVSExpectation, SVSTechniqueWorklist, User
from saq.database.pool import get_db
from saq.gui.filter_screens import SVS_WORKLIST_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.svs import worklist
from saq.svs.attack import get_attack_catalog
from saq.svs.constants import ExpectationState
from saq.svs.coverage import measured_by_signature
from saq.svs.samples import to_utc_naive
from saq.svs.test_state import evaluate_tests
from saq.svs.worklist_filters import worklist_filter_conditions

# the listing orders: the screen's, or (updated_at, id) for a changed_since pull
LISTING_ORDER_SIGNATURE = "signature"
LISTING_ORDER_UPDATED = "updated_at"

ORDER_COLUMNS = {
    LISTING_ORDER_SIGNATURE: ("signature_uuid", "technique", "id"),
    LISTING_ORDER_UPDATED: ("updated_at", "id"),
}
CURSOR_VALUES = {"updated_at": datetime.fromisoformat, "id": int, "signature_uuid": str, "technique": str}


@dataclass(frozen=True)
class WorklistListing:
    statement: Select
    order: str


def _filter_entries(filter_params: list[str]) -> list[dict]:
    try:
        entries, _ = decode_filter_query(filter_params, screen=SVS_WORKLIST_SCREEN, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        return [entry.model_dump() for entry in SVS_WORKLIST_SCREEN.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))


def prepare_listing(filter_params: list[str], *, changed_since: datetime | None, tz) -> WorklistListing:
    """Builds the listing statement from share-link filters (`f=`) of the worklist screen. Raises
    InvalidListingRequest."""
    statement = select(SVSTechniqueWorklist).where(*worklist_filter_conditions(_filter_entries(filter_params), tz))
    if changed_since is None:
        return WorklistListing(statement, LISTING_ORDER_SIGNATURE)
    return WorklistListing(statement.where(SVSTechniqueWorklist.updated_at >= to_utc_naive(changed_since)),
                           LISTING_ORDER_UPDATED)


def _usernames(rows: list[SVSTechniqueWorklist]) -> dict[int, str]:
    ids = sorted({row.resolved_by_user_id for row in rows if row.resolved_by_user_id is not None})
    if not ids:
        return {}
    return dict(get_db().execute(select(User.id, User.username).where(User.id.in_(ids))).tuples().all())


def _technique_name(technique: str) -> Optional[str]:
    known = get_attack_catalog().technique(technique)
    return known.name if known is not None else None


def _rows(rows: list[SVSTechniqueWorklist]) -> list[WorklistRow]:
    usernames = _usernames(rows)
    return [WorklistRow(
        signature_uuid=row.signature_uuid, technique=row.technique, technique_name=_technique_name(row.technique),
        kind=row.kind, status=row.status, declared_as=json.loads(row.declared_as), tag_present=row.tag_present,
        signature_counts=row.signature_counts, counts=row.counts, measured=row.measured,
        measured_techniques=json.loads(row.measured_techniques), signature_family=row.signature_family,
        signature_name=row.signature_name, resolution=row.resolution, reason=row.reason, reference=row.reference,
        resolved_by=usernames.get(row.resolved_by_user_id), resolved_at=row.resolved_at,
        first_seen_at=row.first_seen_at, status_changed_at=row.status_changed_at, updated_at=row.updated_at)
        for row in rows]


def fetch_page(listing: WorklistListing, cursor: str | None, limit: int) -> tuple[list[WorklistRow], str | None]:
    """One page of the listing after `cursor`, and the next page's cursor (None on the last).
    Raises InvalidCursor."""
    rows, next_cursor = keyset_page(get_db(), listing.statement, SVSTechniqueWorklist, listing.order, ORDER_COLUMNS,
                                    CURSOR_VALUES, cursor, limit, settle_order=LISTING_ORDER_UPDATED,
                                    settle_seconds=CHANGED_SINCE_SETTLE_SECONDS)
    return _rows(rows), next_cursor


def worklist_rows_to_csv(rows: list[WorklistRow], *, header: bool) -> str:
    def flatten(values: dict) -> None:
        values["declared_as"] = ",".join(values["declared_as"])
        values["measured_techniques"] = ",".join(values["measured_techniques"])

    return rows_to_csv(rows, WORKLIST_CSV_FIELDS, header=header, flatten=flatten)


#
# a signature
#

def _measured(signature_uuid: str) -> list[MeasuredTechnique]:
    """What the signature is measured on now: the tests that expect it, ignores applied."""
    db = get_db()
    guids = db.execute(select(SVSExpectation.test_guid).distinct().where(
        SVSExpectation.signature_uuid == signature_uuid,
        SVSExpectation.state == ExpectationState.EXPECTED.value)).scalars().all()
    if not guids:
        return []

    tests = list(db.execute(select(SVSCatalogTest).where(
        SVSCatalogTest.guid.in_(guids), SVSCatalogTest.removed_at.is_(None))).scalars())
    names = {test.guid: test.name for test in tests}
    catalog = get_attack_catalog()
    measured = measured_by_signature(catalog, tests, evaluate_tests(db, tests)).get(signature_uuid, {})
    return [MeasuredTechnique(technique=technique, technique_name=_technique_name(technique),
                              tests=[MeasuredTest(guid=guid, name=names.get(guid), platform=platform)
                                     for guid, platform in sorted(pairs)])
            for technique, pairs in sorted(measured.items())]


def get_signature(signature_uuid: str) -> SignatureWorklist:
    rows = get_db().execute(select(SVSTechniqueWorklist).where(SVSTechniqueWorklist.signature_uuid == signature_uuid)
                            .order_by(SVSTechniqueWorklist.technique, SVSTechniqueWorklist.id)).scalars().all()
    if not rows:
        raise HTTPException(status_code=404, detail=f"signature {signature_uuid} has no worklist rows")

    # the family and name as the latest refresh knew them
    latest = max(rows, key=lambda row: row.updated_at)
    return SignatureWorklist(signature_uuid=rows[0].signature_uuid, signature_family=latest.signature_family,
                             signature_name=latest.signature_name, rows=_rows(rows),
                             measured=_measured(rows[0].signature_uuid))


#
# resolving (svs:run_manage)
#

def _errors(e: Exception) -> HTTPException:
    if isinstance(e, worklist.UnknownWorklistRow):
        return HTTPException(status_code=404, detail=str(e))
    if isinstance(e, worklist.WorklistConflict):
        return HTTPException(status_code=409, detail=str(e))
    return HTTPException(status_code=422, detail=str(e))


def set_resolution(signature_uuid: str, technique: str, body: ResolutionRequest, user_id: Optional[int],
                   actor: Optional[str]) -> WorklistRow:
    user_id = require_user(user_id)
    try:
        row = worklist.resolve(signature_uuid, technique, body.resolution, body.reason, user_id,
                               reference=body.reference, actor=actor)
    except (worklist.UnknownWorklistRow, worklist.WorklistConflict, worklist.InvalidResolution) as e:
        raise _errors(e)
    return _rows([row])[0]


def clear_resolution(signature_uuid: str, technique: str, user_id: Optional[int], actor: Optional[str]) -> None:
    user_id = require_user(user_id)
    try:
        worklist.reopen(signature_uuid, technique, user_id, actor=actor)
    except worklist.UnknownWorklistRow as e:
        raise _errors(e)


def bulk_resolve(body: BulkResolutionRequest, user_id: Optional[int], actor: Optional[str]) -> BulkResolutionResult:
    user_id = require_user(user_id)
    try:
        result = worklist.resolve_many([(key.signature_uuid, key.technique) for key in body.rows], body.resolution,
                                       body.reason, user_id, reference=body.reference, actor=actor)
    except worklist.InvalidResolution as e:
        raise _errors(e)
    return BulkResolutionResult(
        done=[WorklistKey(signature_uuid=sig, technique=technique) for sig, technique in result.done],
        conflicts=[WorklistConflictItem(signature_uuid=sig, technique=technique, status=status)
                   for (sig, technique), status in result.conflicts.items()],
        unknown=[WorklistKey(signature_uuid=sig, technique=technique) for sig, technique in result.unknown])
