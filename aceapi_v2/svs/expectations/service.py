"""SVS expectations and test settings service for ACE API v2 (docs/SVS_RUNS.md, *Expectations and
ignores*, *Windows*; docs/SVS_API.md).

Synchronous; the routers run each function through run_db_in_thread. saq.svs.expectations owns the
decisions; this pages them and maps its errors to HTTP.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import aliased

from aceapi_v2.common.listing import (
    CHANGED_SINCE_SETTLE_SECONDS,
    InvalidListingRequest,
    decode_cursor,
    encode_cursor,
    rows_to_csv,
    settled,
)
from aceapi_v2.svs.expectations.schemas import (
    EXPECTATION_CSV_FIELDS,
    Expectation,
    ExpectationRequest,
    TestSettings,
    TestSettingsRequest,
)
from saq.database.model import SVSExpectation, SVSRun, SVSTestSettings, User
from saq.database.pool import get_db
from saq.svs import expectations
from saq.svs.constants import ExpectationState
from saq.svs.samples import to_utc_naive


def require_user(user_id: Optional[int]) -> int:
    # every decision records who made it; a config API key belongs to nobody
    if user_id is None:
        raise HTTPException(status_code=422, detail="this action records who took it: it requires a user's API key or session")
    return user_id


def decision_errors(e: Exception) -> HTTPException:
    """The HTTP answer to an error of saq.svs.expectations."""
    if isinstance(e, (expectations.UnknownTest, expectations.UnknownDecision)):
        return HTTPException(status_code=404, detail=str(e))
    return HTTPException(status_code=422, detail=str(e))


#
# reading
#

def _statement() -> Select:
    decided_by = aliased(User)
    return (select(SVSExpectation, SVSRun.uuid, decided_by.username)
            .outerjoin(SVSRun, SVSRun.id == SVSExpectation.decided_from_run_id)
            .outerjoin(decided_by, decided_by.id == SVSExpectation.decided_by_user_id))


def _row(row) -> Expectation:
    expectation, run_uuid, username = row
    return Expectation(
        test_guid=expectation.test_guid, platform=expectation.platform, signature_uuid=expectation.signature_uuid,
        state=expectation.state,
        signature_family=expectation.signature_family, signature_name=expectation.signature_name,
        reason=expectation.reason, decided_from_run_id=run_uuid, decided_by=username,
        decided_at=expectation.decided_at, updated_at=expectation.updated_at)


@dataclass(frozen=True)
class ExpectationListing:
    statement: Select
    changed_since: bool


def prepare_listing(test: Optional[str], platform: Optional[str], signature: Optional[str], state: Optional[str],
                    changed_since: Optional[datetime]) -> ExpectationListing:
    """The expectations matching the filters. Raises InvalidListingRequest."""
    statement = _statement()
    if test:
        statement = statement.where(SVSExpectation.test_guid == test.strip())
    if platform:
        statement = statement.where(SVSExpectation.platform == platform.strip().lower())
    if signature:
        statement = statement.where(SVSExpectation.signature_uuid == signature.strip())
    if state:
        if state not in {s.value for s in ExpectationState}:
            raise InvalidListingRequest(f"state must be one of {', '.join(s.value for s in ExpectationState)}")
        statement = statement.where(SVSExpectation.state == state)
    if changed_since is not None:
        statement = statement.where(SVSExpectation.updated_at >= to_utc_naive(changed_since))
    return ExpectationListing(statement=statement, changed_since=changed_since is not None)


def _parse_id(payload: dict) -> int:
    (row_id,) = payload["k"]
    return int(row_id)


def _parse_changed_key(payload: dict) -> tuple[datetime, int]:
    updated_at, row_id = payload["k"]
    return datetime.fromisoformat(updated_at), int(row_id)


def fetch_page(listing: ExpectationListing, cursor: str | None, limit: int) -> tuple[list[Expectation], str | None]:
    """One page in id order, or with changed_since in (updated_at, id) order of settled rows.
    Raises InvalidCursor."""
    statement = listing.statement
    if listing.changed_since:
        statement = statement.where(settled(SVSExpectation.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
        if cursor is not None:
            updated_at, row_id = decode_cursor(cursor, _parse_changed_key)
            statement = statement.where(or_(
                SVSExpectation.updated_at > updated_at,
                and_(SVSExpectation.updated_at == updated_at, SVSExpectation.id > row_id)))
        statement = statement.order_by(SVSExpectation.updated_at, SVSExpectation.id)
    else:
        if cursor is not None:
            statement = statement.where(SVSExpectation.id > decode_cursor(cursor, _parse_id))
        statement = statement.order_by(SVSExpectation.id)

    rows = get_db().execute(statement.limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1][0]
        next_cursor = (encode_cursor(k=[last.updated_at.isoformat(), last.id]) if listing.changed_since
                       else encode_cursor(k=[last.id]))

    return [_row(row) for row in rows], next_cursor


def expectations_to_csv(rows: list[Expectation], *, header: bool) -> str:
    return rows_to_csv(rows, EXPECTATION_CSV_FIELDS, header=header)


def _expectation(test_guid: str, platform: str, signature_uuid: str) -> Expectation:
    row = get_db().execute(_statement().where(
        SVSExpectation.test_guid == test_guid, SVSExpectation.platform == platform,
        SVSExpectation.signature_uuid == signature_uuid)).one()
    return _row(row)


#
# deciding (svs:run_manage)
#

def set_expectation(guid: str, platform: str, signature_uuid: str, body: ExpectationRequest, user_id: Optional[int],
                    actor: Optional[str]) -> Expectation:
    user_id = require_user(user_id)
    try:
        expectation = expectations.set_expectation(guid, signature_uuid, body.state, user_id, platform=platform,
                                                   reason=body.reason, run_uuid=body.run_id, actor=actor)
    except (expectations.UnknownTest, expectations.InvalidDecision) as e:
        raise decision_errors(e)
    return _expectation(expectation.test_guid, expectation.platform, expectation.signature_uuid)


def remove_expectation(guid: str, platform: str, signature_uuid: str, user_id: Optional[int],
                       actor: Optional[str]) -> None:
    user_id = require_user(user_id)
    try:
        expectations.remove_expectation(guid, platform, signature_uuid, user_id, actor=actor)
    except (expectations.UnknownTest, expectations.UnknownDecision, expectations.InvalidDecision) as e:
        raise decision_errors(e)


#
# settings (read: svs:run_read; write: svs:run_manage)
#

def _settings(settings: SVSTestSettings) -> TestSettings:
    username = None
    if settings.set_by_user_id is not None:
        username = get_db().execute(select(User.username).where(User.id == settings.set_by_user_id)).scalar()
    return TestSettings(test_guid=settings.test_guid, observation_minutes=settings.observation_minutes,
                        set_by=username, updated_at=settings.updated_at)


def get_test_settings(guid: str) -> TestSettings:
    """404 for an unknown test, or one without settings."""
    try:
        settings = expectations.get_test_settings(guid)
    except expectations.UnknownTest as e:
        raise decision_errors(e)
    if settings is None:
        raise HTTPException(status_code=404, detail=f"test {guid} has no settings")
    return _settings(settings)


def set_test_settings(guid: str, body: TestSettingsRequest, user_id: Optional[int], actor: Optional[str]) -> TestSettings:
    user_id = require_user(user_id)
    try:
        settings = expectations.set_test_settings(guid, user_id, observation_minutes=body.observation_minutes,
                                                  actor=actor)
    except (expectations.UnknownTest, expectations.InvalidDecision) as e:
        raise decision_errors(e)
    return _settings(settings)


def remove_test_settings(guid: str, user_id: Optional[int], actor: Optional[str]) -> None:
    user_id = require_user(user_id)
    try:
        expectations.remove_test_settings(guid, user_id, actor=actor)
    except (expectations.UnknownTest, expectations.UnknownDecision) as e:
        raise decision_errors(e)
