"""SVS ignores service for ACE API v2 (docs/SVS_RUNS.md, *Expectations and ignores*; docs/SVS_API.md).

Synchronous; the routers run each function through run_db_in_thread. saq.svs.expectations owns the
ignores; this pages them and maps its errors to HTTP.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import Select, and_, or_, select

from aceapi_v2.common.listing import (
    CHANGED_SINCE_SETTLE_SECONDS,
    InvalidListingRequest,
    decode_cursor,
    encode_cursor,
    rows_to_csv,
    settled,
)
from aceapi_v2.svs.expectations.service import decision_errors, require_user
from aceapi_v2.svs.ignores.schemas import IGNORE_CSV_FIELDS, Ignore, IgnoreRequest
from saq.database.model import SVSIgnore, User
from saq.database.pool import get_db
from saq.svs import expectations
from saq.svs.constants import GLOBAL_SCOPE_KEY, IgnoreScope
from saq.svs.samples import to_utc_naive


def _statement() -> Select:
    return select(SVSIgnore, User.username).outerjoin(User, User.id == SVSIgnore.created_by_user_id)


def _row(row) -> Ignore:
    ignore, username = row
    return Ignore(scope=ignore.scope, test_guid=ignore.test_guid, signature_uuid=ignore.signature_uuid,
                  signature_family=ignore.signature_family, signature_name=ignore.signature_name,
                  reason=ignore.reason, created_by=username, created_at=ignore.created_at,
                  updated_at=ignore.updated_at)


@dataclass(frozen=True)
class IgnoreListing:
    statement: Select
    changed_since: bool


def prepare_listing(scope: Optional[str], test: Optional[str], signature: Optional[str],
                    changed_since: Optional[datetime]) -> IgnoreListing:
    """The ignores matching the filters; test also finds the global ones, which apply to it.
    Raises InvalidListingRequest."""
    statement = _statement()
    if scope:
        if scope not in {s.value for s in IgnoreScope}:
            raise InvalidListingRequest(f"scope must be one of {', '.join(s.value for s in IgnoreScope)}")
        statement = statement.where(SVSIgnore.scope == scope)
    if test:
        statement = statement.where(SVSIgnore.scope_key.in_([GLOBAL_SCOPE_KEY, test.strip()]))
    if signature:
        statement = statement.where(SVSIgnore.signature_uuid == signature.strip())
    if changed_since is not None:
        statement = statement.where(SVSIgnore.updated_at >= to_utc_naive(changed_since))
    return IgnoreListing(statement=statement, changed_since=changed_since is not None)


def _parse_id(payload: dict) -> int:
    (row_id,) = payload["k"]
    return int(row_id)


def _parse_changed_key(payload: dict) -> tuple[datetime, int]:
    updated_at, row_id = payload["k"]
    return datetime.fromisoformat(updated_at), int(row_id)


def fetch_page(listing: IgnoreListing, cursor: str | None, limit: int) -> tuple[list[Ignore], str | None]:
    """One page in id order, or with changed_since in (updated_at, id) order of settled rows.
    Raises InvalidCursor."""
    statement = listing.statement
    if listing.changed_since:
        statement = statement.where(settled(SVSIgnore.updated_at, CHANGED_SINCE_SETTLE_SECONDS))
        if cursor is not None:
            updated_at, row_id = decode_cursor(cursor, _parse_changed_key)
            statement = statement.where(or_(
                SVSIgnore.updated_at > updated_at, and_(SVSIgnore.updated_at == updated_at, SVSIgnore.id > row_id)))
        statement = statement.order_by(SVSIgnore.updated_at, SVSIgnore.id)
    else:
        if cursor is not None:
            statement = statement.where(SVSIgnore.id > decode_cursor(cursor, _parse_id))
        statement = statement.order_by(SVSIgnore.id)

    rows = get_db().execute(statement.limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1][0]
        next_cursor = (encode_cursor(k=[last.updated_at.isoformat(), last.id]) if listing.changed_since
                       else encode_cursor(k=[last.id]))

    return [_row(row) for row in rows], next_cursor


def ignores_to_csv(rows: list[Ignore], *, header: bool) -> str:
    return rows_to_csv(rows, IGNORE_CSV_FIELDS, header=header)


def _ignore(ignore: SVSIgnore) -> Ignore:
    return _row(get_db().execute(_statement().where(SVSIgnore.id == ignore.id)).one())


def set_ignore(signature_uuid: str, body: IgnoreRequest, user_id: Optional[int], actor: Optional[str],
               test_guid: Optional[str] = None) -> Ignore:
    """A test's ignore (svs:run_manage), or a global one when test_guid is None (svs:admin)."""
    user_id = require_user(user_id)
    try:
        ignore = expectations.set_ignore(signature_uuid, user_id, test_guid=test_guid, reason=body.reason, actor=actor)
    except (expectations.UnknownTest, expectations.InvalidDecision) as e:
        raise decision_errors(e)
    return _ignore(ignore)


def remove_ignore(signature_uuid: str, user_id: Optional[int], actor: Optional[str],
                  test_guid: Optional[str] = None) -> None:
    user_id = require_user(user_id)
    try:
        expectations.remove_ignore(signature_uuid, user_id, test_guid=test_guid, actor=actor)
    except (expectations.UnknownTest, expectations.UnknownDecision, expectations.InvalidDecision) as e:
        raise decision_errors(e)
