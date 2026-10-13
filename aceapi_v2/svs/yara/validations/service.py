"""SVS YARA validation service for ACE API v2 (docs/SVS_VALIDATION.md, docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread (or run_in_threadpool for the
CAS work). saq.svs.validations owns the queue; this reads it.

Two audiences. The signature repository's CI holds svs:validate only: it requests a validation and
reads its status, which carries counts and rule names and uuids, never a sample's sha256, file name
or content. Everyone with signature:read reads the listing, the reports and their rows, which name
the samples; their files need signature:download.
"""

import base64
import csv
import io
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, and_, func, or_, select

from aceapi_v2.svs.samples.service import InvalidCursor, InvalidListingRequest, SampleDownload, bulk_download
from aceapi_v2.svs.yara.validations.schemas import (
    VALIDATION_RESULT_CSV_FIELDS,
    VALIDATION_ROW_CSV_FIELDS,
    CompileProblem,
    RuleCount,
    ValidationDetail,
    ValidationRequest,
    ValidationResultRow,
    ValidationRow,
    ValidationStatus,
)
from saq.configuration.config import get_config
from saq.database.model import SVSValidation, SVSValidationResult, User
from saq.database.pool import get_db
from saq.gui.filter_screens import SVS_VALIDATIONS_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.signatures.model import SIGNATURE_UUID_PATTERN
from saq.svs.samples import samples_subquery, to_utc_naive
from saq.svs.validation_filters import validation_filter_conditions
from saq.svs.validations import get_validation, request_validation
from saq.svs.yara.diff import COUNTED_ONLY, Category
from saq.svs.yara.layout import LayoutError
from saq.util.uuid import UUID_REGEX

logger = logging.getLogger(__name__)

LISTING_MAX_PAGE_SIZE = 1000
LISTING_EXPORT_PAGE_SIZE = 1000

_CURSOR_VERSION = 1

# the categories a report lists rows for, in the order of the report's bands
LISTED_CATEGORIES = tuple(category.value for category in Category if category not in COUNTED_ONLY)


def report_path(validation_uuid: str) -> str:
    """Where the GUI shows the report, relative to its host."""
    return f"/ace/signatures/validations/{validation_uuid}"


def _require_user(user_id: int | None) -> int:
    # every request records who made it; a config API key belongs to nobody
    if user_id is None:
        raise HTTPException(status_code=422, detail="a validation records who requested it: it requires a user's API key")

    return user_id


def _validate_uuid(validation_uuid: str) -> str:
    validation_uuid = validation_uuid.lower()
    if not UUID_REGEX.fullmatch(validation_uuid):
        raise HTTPException(status_code=400, detail="invalid validation uuid")
    return validation_uuid


def _require_validation(validation_uuid: str) -> SVSValidation:
    validation = get_validation(_validate_uuid(validation_uuid))
    if validation is None:
        raise HTTPException(status_code=404, detail="validation not found")
    return validation


def _json(value: Optional[str]) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except ValueError:
        logger.warning("unreadable JSON in an svs validation: %.80r", value)
        return None


#
# CI: request and status
#

def request(body: ValidationRequest, user_id: int | None) -> tuple[ValidationStatus, bool]:
    """The validation that answers the request, and whether it is new. 422 for a repository that
    cannot be validated, or a key with no user."""
    user_id = _require_user(user_id)
    if body.repository not in get_config().svs.yara.repositories:
        raise HTTPException(status_code=422, detail=f"repository {body.repository!r} is not in svs.yara.repositories")

    try:
        validation_uuid, created = request_validation(
            body.repository, body.base_sha, body.head_sha, body.branch, body.pr_url, user_id)
    except LayoutError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return get_status(validation_uuid), created


def _rules(validation_id: int) -> dict[str, list[RuleCount]]:
    rows = get_db().execute(
        select(SVSValidationResult.category, SVSValidationResult.rule_uuid, SVSValidationResult.rule_name,
               func.count().label("count"))
        .where(SVSValidationResult.validation_id == validation_id)
        .group_by(SVSValidationResult.category, SVSValidationResult.rule_uuid, SVSValidationResult.rule_name)
        .order_by(func.count().desc(), SVSValidationResult.rule_name)).all()
    rules: dict[str, list[RuleCount]] = {}
    for row in rows:
        rules.setdefault(row.category, []).append(
            RuleCount(rule_uuid=row.rule_uuid, rule_name=row.rule_name, count=row.count))

    return {category: rules[category] for category in LISTED_CATEGORIES if category in rules}


def get_status(validation_uuid: str) -> ValidationStatus:
    validation = _require_validation(validation_uuid)
    report = _json(validation.report) or {}
    head = report.get("head") or {}
    return ValidationStatus(
        uuid=validation.uuid, state=validation.state, error=validation.error,
        repository=validation.repository, base_sha=validation.base_sha, head_sha=validation.head_sha,
        branch=validation.branch, pr_url=validation.pr_url, created_at=validation.created_at,
        started_at=validation.started_at, finished_at=validation.finished_at, diffed=validation.diffed,
        counts=_json(validation.counts), rules=_rules(validation.id),
        compile_errors=[CompileProblem(file=error["file"], error=error["error"]) for error in head.get("file_errors", [])],
        ruleset_error=head.get("ruleset_error"), report_path=report_path(validation.uuid))


#
# the listing, paged by keyset on (created_at, id), newest first
#

@dataclass(frozen=True)
class ValidationListing:
    statement: Select


def _filter_entries(filter_params: list[str]) -> list[dict]:
    try:
        entries, _ = decode_filter_query(filter_params, screen=SVS_VALIDATIONS_SCREEN, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        return [entry.model_dump() for entry in SVS_VALIDATIONS_SCREEN.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))


def prepare_listing(filter_params: list[str], *, changed_since: datetime | None, tz) -> ValidationListing:
    """Builds the listing statement from share-link filters (`f=`) of the validations screen.
    Raises InvalidListingRequest."""
    statement = (select(SVSValidation, User.username)
                 .outerjoin(User, User.id == SVSValidation.requested_by))
    for condition in validation_filter_conditions(_filter_entries(filter_params), tz):
        statement = statement.where(condition)

    if changed_since is not None:
        statement = statement.where(SVSValidation.updated_at >= to_utc_naive(changed_since))

    return ValidationListing(statement=statement)


def _encode_cursor(key: list) -> str:
    payload = json.dumps({"v": _CURSOR_VERSION, "k": key}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> list:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if payload["v"] != _CURSOR_VERSION:
            raise InvalidCursor(f"unsupported cursor version {payload['v']!r}")
        return payload["k"]
    except InvalidCursor:
        raise
    except Exception as e:
        raise InvalidCursor(f"malformed cursor: {e}") from None


def _row(validation: SVSValidation, username: Optional[str]) -> ValidationRow:
    return ValidationRow(
        uuid=validation.uuid, repository=validation.repository, base_sha=validation.base_sha,
        head_sha=validation.head_sha, branch=validation.branch, pr_url=validation.pr_url,
        state=validation.state, requested_by=username, created_at=validation.created_at,
        started_at=validation.started_at, finished_at=validation.finished_at, error=validation.error,
        diffed=validation.diffed, regressions=validation.regressions, new_fps=validation.new_fps,
        compile_errors=validation.compile_errors, counts=_json(validation.counts),
        updated_at=validation.updated_at)


def fetch_page(listing: ValidationListing, cursor: str | None, limit: int) -> tuple[list[ValidationRow], str | None]:
    """One page of the listing after `cursor`, and the next page's cursor (None on the last).
    Raises InvalidCursor."""
    statement = listing.statement
    if cursor is not None:
        try:
            created_at, row_id = _decode_cursor(cursor)
            created_at, row_id = datetime.fromisoformat(created_at), int(row_id)
        except InvalidCursor:
            raise
        except Exception as e:
            raise InvalidCursor(f"malformed cursor: {e}") from None

        statement = statement.where(or_(
            SVSValidation.created_at < created_at,
            and_(SVSValidation.created_at == created_at, SVSValidation.id < row_id)))

    rows = get_db().execute(
        statement.order_by(SVSValidation.created_at.desc(), SVSValidation.id.desc()).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1][0]
        next_cursor = _encode_cursor([last.created_at.isoformat(), last.id])

    return [_row(validation, username) for validation, username in rows], next_cursor


def _to_csv(rows: list, fields: tuple[str, ...], *, header: bool) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if header:
        writer.writerow(fields)
    for row in rows:
        values = row.model_dump(mode="json")
        writer.writerow([values[name] if values[name] is not None else "" for name in fields])
    return buffer.getvalue()


def rows_to_csv(rows: list[ValidationRow], *, header: bool) -> str:
    return _to_csv(rows, VALIDATION_ROW_CSV_FIELDS, header=header)


#
# one validation
#

def get_detail(validation_uuid: str) -> ValidationDetail:
    validation = _require_validation(validation_uuid)
    username = validation.requested_by_user.username if validation.requested_by_user is not None else None
    return ValidationDetail(
        **_row(validation, username).model_dump(), attempts=validation.attempts, claimed_by=validation.claimed_by,
        corpus_version=validation.corpus_version, engine_fingerprint=validation.engine_fingerprint,
        report=_json(validation.report))


#
# its results, paged by keyset on id
#

@dataclass(frozen=True)
class ResultSelection:
    validation_id: int
    validation_uuid: str
    categories: tuple[str, ...]
    rule_uuids: tuple[str, ...]

    def conditions(self) -> list:
        conditions = [SVSValidationResult.validation_id == self.validation_id]
        if self.categories:
            conditions.append(SVSValidationResult.category.in_(self.categories))
        if self.rule_uuids:
            conditions.append(SVSValidationResult.rule_uuid.in_(self.rule_uuids))
        return conditions


def select_results(validation_uuid: str, categories: list[str], rule_uuids: list[str]) -> ResultSelection:
    """The rows of a validation, narrowed to categories and rules. 404 for an unknown validation,
    422 for an unknown category or a malformed rule uuid."""
    unknown = [category for category in categories if category not in LISTED_CATEGORIES]
    if unknown:
        raise HTTPException(status_code=422, detail=(
            f"unknown or counted-only categories {', '.join(unknown)} (listed: {', '.join(LISTED_CATEGORIES)})"))
    malformed = [rule_uuid for rule_uuid in rule_uuids if not SIGNATURE_UUID_PATTERN.match(rule_uuid)]
    if malformed:
        raise HTTPException(status_code=422, detail=f"invalid rule uuids {', '.join(malformed)}")

    validation = _require_validation(validation_uuid)
    return ResultSelection(validation.id, validation.uuid, tuple(categories), tuple(rule_uuids))


def fetch_results_page(selection: ResultSelection, cursor: str | None, limit: int) -> tuple[list[ValidationResultRow], str | None]:
    """One page of the selected rows after `cursor`, in id order, and the next page's cursor.
    Raises InvalidCursor."""
    statement = select(SVSValidationResult).where(*selection.conditions())
    if cursor is not None:
        try:
            (after,) = _decode_cursor(cursor)
            after = int(after)
        except InvalidCursor:
            raise
        except Exception as e:
            raise InvalidCursor(f"malformed cursor: {e}") from None
        statement = statement.where(SVSValidationResult.id > after)

    rows = get_db().execute(statement.order_by(SVSValidationResult.id).limit(limit + 1)).scalars().all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = _encode_cursor([rows[-1].id])

    return [ValidationResultRow(
        id=row.id, sha256=row.sha256, rule_uuid=row.rule_uuid, rule_name=row.rule_name, namespace=row.namespace,
        label=row.label, label_source=row.label_source, base=row.base, head=row.head, raw_base=row.raw_base,
        raw_head=row.raw_head, category=row.category, note=row.note) for row in rows], next_cursor


def results_to_csv(rows: list[ValidationResultRow], *, header: bool) -> str:
    return _to_csv(rows, VALIDATION_RESULT_CSV_FIELDS, header=header)


def resolve_results_download(selection: ResultSelection) -> SampleDownload:
    """The files of the selected rows, with the match records of every sample of each file (a row of
    another rule's sample has no sample of its own). The samples download's limits and wrong_node
    handling apply."""
    samples = samples_subquery()
    sha256s = select(SVSValidationResult.sha256).where(*selection.conditions()).distinct()
    return bulk_download(samples, select(samples).where(samples.c.sha256.in_(sha256s)))
