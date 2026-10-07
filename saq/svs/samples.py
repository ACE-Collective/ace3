"""Reading the SVS YARA samples: one row per (file sha256, rule uuid), aggregated from the
captures in svs_yara_captures, with its label (saq.svs.labels). docs/SVS_SAMPLES.md describes the
data, docs/SVS_API.md the API that serves it (aceapi_v2/svs/samples/).

Everything here builds SQL or runs it on the caller's get_db() session; nothing writes.
"""

import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable, Optional

from sqlalchemy import Select, and_, case, exists, func, literal, or_, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import (
    Alert,
    DetectionPoint,
    DetectionPointVerdictHistory,
    SVSYaraCapture,
)
from saq.database.pool import get_db
from saq.detection_verdicts.query import detection_points_select
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.svs.constants import CaptureState
from saq.svs.labels import (
    VOTE_COLUMNS,
    Votes,
    contributing_detection_condition,
    label_expr,
    label_source_expr,
    sample_votes_subquery,
)


def _count_where(condition) -> ColumnElement:
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def samples_subquery():
    """Every sample, one row per (sha256, rule_uuid):

    - capture_count, stored, missing: how many captures it has, and how many are stored or missing;
    - missing_data: how many captures lack something (a missing_reason: no file, or no match record);
    - unknown_version: how many were captured with signature version 'unknown';
    - first_captured, last_captured, updated_at: over its captures;
    - latest_capture_id and that capture's rule_name, namespace, file_path and file_size;
    - the vote counts (VOTE_COLUMNS), label and label_source.

    Filters and sorts name the columns of the returned subquery (.c)."""
    capture = SVSYaraCapture
    grouped = (
        select(
            capture.sha256,
            capture.rule_uuid,
            func.count().label("capture_count"),
            _count_where(capture.state == CaptureState.STORED).label("stored"),
            _count_where(capture.state == CaptureState.MISSING).label("missing"),
            _count_where(capture.missing_reason.is_not(None)).label("missing_data"),
            _count_where(capture.signature_version == SIGNATURE_VERSION_UNKNOWN).label("unknown_version"),
            func.min(capture.created_at).label("first_captured"),
            func.max(capture.created_at).label("last_captured"),
            func.max(capture.updated_at).label("updated_at"),
            func.max(capture.id).label("latest_capture_id"),
        )
        .group_by(capture.sha256, capture.rule_uuid)
        .subquery("sample_captures"))

    latest = aliased(SVSYaraCapture, name="latest_capture")
    votes = sample_votes_subquery()
    return (
        select(
            grouped,
            latest.rule_name,
            latest.namespace,
            latest.file_path,
            latest.file_size,
            *[func.coalesce(votes.c[name], 0).label(name) for name, _, _ in VOTE_COLUMNS],
            label_expr(votes.c).label("label"),
            label_source_expr(votes.c).label("label_source"),
        )
        .select_from(grouped)
        .join(latest, latest.id == grouped.c.latest_capture_id)
        .outerjoin(votes, and_(votes.c.sha256 == grouped.c.sha256, votes.c.rule_uuid == grouped.c.rule_uuid))
        .subquery("samples"))


def captures_of(samples) -> ColumnElement[bool]:
    """The condition that ties a capture (the SVSYaraCapture entity) to a row of samples."""
    return and_(SVSYaraCapture.sha256 == samples.c.sha256, SVSYaraCapture.rule_uuid == samples.c.rule_uuid)


def _to_utc_naive(value: datetime) -> datetime:
    # the capture timestamps are naive UTC, and TIMESTAMP columns compare in the session time
    # zone, which ACE runs as UTC
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def changed_since_condition(samples, value: datetime) -> ColumnElement[bool]:
    """A sample whose data may have changed at or after `value`: a capture of it changed (or was
    added), a contributing alert's row changed (a disposition, which relabels it), or a
    contributing detection's stored verdict was set or cleared (a cleared verdict leaves no row of
    its own, which is why the history is the signal). An alert that is deleted bumps nothing."""
    value = _to_utc_naive(value)
    history = (
        select(literal(1))
        .where(DetectionPointVerdictHistory.alert_id == DetectionPoint.alert_id)
        .where(DetectionPointVerdictHistory.content_hash == DetectionPoint.content_hash)
        .where(DetectionPointVerdictHistory.changed_at >= value))
    contributing = (
        select(literal(1))
        .select_from(SVSYaraCapture)
        .join(Alert, Alert.uuid == SVSYaraCapture.alert_uuid)
        .join(DetectionPoint, and_(
            DetectionPoint.alert_id == Alert.id,
            contributing_detection_condition(SVSYaraCapture, DetectionPoint)))
        .where(captures_of(samples))
        .where(or_(Alert.updated_at >= value, exists(history))))
    return or_(samples.c.updated_at >= value, exists(contributing))


#
# sorting and keyset paging
#

class SampleSort(StrEnum):
    LAST_CAPTURED = "last_captured"
    FIRST_CAPTURED = "first_captured"
    CAPTURE_COUNT = "capture_count"
    RULE = "rule"
    LABEL = "label"
    SHA256 = "sha256"


_DATE_SORTS = (SampleSort.LAST_CAPTURED, SampleSort.FIRST_CAPTURED)


def sort_value(samples, sort: SampleSort) -> ColumnElement:
    """The value a sort orders by. Never NULL, so it can be a keyset column."""
    if sort == SampleSort.RULE:
        return samples.c.rule_name
    if sort == SampleSort.LABEL:
        return func.coalesce(samples.c.label, "")
    return samples.c[sort.value]


def keyset_condition(samples, sort: SampleSort, descending: bool, key: list) -> ColumnElement[bool]:
    """The rows after `key` ([sort value, sha256, rule_uuid]) in the listing's order, written out
    rather than as a row comparison so mysql can use a range."""
    value, sha256, rule_uuid = key
    columns = (sort_value(samples, sort), samples.c.sha256, samples.c.rule_uuid)

    def after(column, bound):
        return column < bound if descending else column > bound

    return or_(
        after(columns[0], value),
        and_(columns[0] == value, after(columns[1], sha256)),
        and_(columns[0] == value, columns[1] == sha256, after(columns[2], rule_uuid)))


def order_by(samples, sort: SampleSort, descending: bool) -> list:
    columns = (sort_value(samples, sort), samples.c.sha256, samples.c.rule_uuid)
    return [column.desc() if descending else column.asc() for column in columns]


def sort_key(record: dict, sort: SampleSort) -> list:
    """The keyset of a row, JSON-ready: [sort value, sha256, rule_uuid]."""
    if sort == SampleSort.RULE:
        value = record["rule_name"]
    elif sort == SampleSort.LABEL:
        value = record["label"] or ""
    elif sort in _DATE_SORTS:
        value = record[sort.value].isoformat()
    else:
        value = record[sort.value]
    return [value, record["sha256"], record["rule_uuid"]]


def parse_sort_key(key: list, sort: SampleSort) -> list:
    """The inverse of sort_key(). Raises ValueError (or TypeError) on a malformed key."""
    value, sha256, rule_uuid = key
    if sort in _DATE_SORTS:
        value = datetime.fromisoformat(value)
    elif sort == SampleSort.CAPTURE_COUNT:
        value = int(value)
    elif not isinstance(value, str):
        raise ValueError(f"invalid sort value {value!r}")
    if not isinstance(sha256, str) or not isinstance(rule_uuid, str):
        raise ValueError("invalid sample key")
    return [value, sha256, rule_uuid]


#
# rows
#

def votes_of(record: dict) -> Votes:
    return Votes(**{name: int(record[name] or 0) for name, _, _ in VOTE_COLUMNS})


def sample_record(record: dict) -> dict[str, Any]:
    """A row of samples_subquery() as plain data, with its counts as ints and its votes grouped."""
    result = {key: value for key, value in record.items() if key not in {name for name, _, _ in VOTE_COLUMNS}}
    for name in ("capture_count", "stored", "missing", "missing_data", "unknown_version"):
        result[name] = int(result[name])
    result["votes"] = votes_of(record).as_dict()
    return result


def get_sample(sha256: str, rule_uuid: str) -> Optional[dict[str, Any]]:
    """One sample, or None."""
    samples = samples_subquery()
    record = get_db().execute(
        select(samples).where(samples.c.sha256 == sha256, samples.c.rule_uuid == rule_uuid)).mappings().one_or_none()
    return sample_record(dict(record)) if record is not None else None


def get_captures(sha256: str, rule_uuid: str) -> list[SVSYaraCapture]:
    """The captures of one sample, newest first."""
    return list(get_db().execute(
        select(SVSYaraCapture)
        .where(SVSYaraCapture.sha256 == sha256, SVSYaraCapture.rule_uuid == rule_uuid)
        .order_by(SVSYaraCapture.id.desc())).scalars())


def get_capture(capture_id: int) -> Optional[SVSYaraCapture]:
    return get_db().get(SVSYaraCapture, capture_id)


def contributing_detections(capture_ids: Iterable[int]) -> dict[int, list[dict[str, Any]]]:
    """capture id -> the detection rows (saq.detection_verdicts.query.detection_points_select)
    that contribute its votes, in detection order. A capture whose alert is gone has none."""
    capture_ids = list(capture_ids)
    if not capture_ids:
        return {}

    statement = (
        detection_points_select()
        .add_columns(SVSYaraCapture.id.label("capture_id"))
        .join(SVSYaraCapture, and_(
            SVSYaraCapture.alert_uuid == Alert.uuid,
            contributing_detection_condition(SVSYaraCapture, DetectionPoint)))
        .where(SVSYaraCapture.id.in_(capture_ids))
        .order_by(DetectionPoint.id))

    result: dict[int, list[dict[str, Any]]] = {capture_id: [] for capture_id in capture_ids}
    for row in get_db().execute(statement).mappings():
        result[row["capture_id"]].append(dict(row))
    return result


def bytes_nodes_statement(sha256s: Iterable[str]) -> Select:
    """(sha256, node) of every stored capture of these files, oldest first: the first row of a
    sha256 is the node its bytes are on. A put writes the bytes to the putting node's backend,
    but a hold on an object another capture stored does not, so with a node-local pool the bytes
    are wherever the first stored capture put them."""
    return (
        select(SVSYaraCapture.sha256, SVSYaraCapture.node)
        .where(SVSYaraCapture.sha256.in_(list(sha256s)), SVSYaraCapture.state == CaptureState.STORED)
        .order_by(SVSYaraCapture.id))


def bytes_nodes(sha256s: Iterable[str]) -> dict[str, str]:
    """sha256 -> the node that has its bytes, for each of these files that has any stored capture."""
    sha256s = set(sha256s)
    if not sha256s:
        return {}

    result: dict[str, str] = {}
    for row in get_db().execute(bytes_nodes_statement(sha256s)):
        result.setdefault(row.sha256, row.node)
    return result


def missing_by_rule() -> list[dict[str, Any]]:
    """How many captures of each rule lack something, per missing_reason, with the rule's latest
    name; the rules with the most first."""
    grouped = (
        select(
            SVSYaraCapture.rule_uuid,
            SVSYaraCapture.missing_reason,
            func.count().label("count"),
            func.max(SVSYaraCapture.id).label("latest_capture_id"))
        .where(SVSYaraCapture.missing_reason.is_not(None))
        .group_by(SVSYaraCapture.rule_uuid, SVSYaraCapture.missing_reason)
        .subquery())
    latest = aliased(SVSYaraCapture)
    statement = (
        select(grouped.c.rule_uuid, latest.rule_name, grouped.c.missing_reason.label("reason"), grouped.c["count"])
        .join(latest, latest.id == grouped.c.latest_capture_id)
        .order_by(grouped.c["count"].desc(), grouped.c.rule_uuid, grouped.c.missing_reason))
    return [dict(row) for row in get_db().execute(statement).mappings()]


def parse_json_column(value: Optional[str], default):
    if not value:
        return default
    try:
        return json.loads(value)
    except ValueError:
        return default

