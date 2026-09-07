"""The lexical lane: exact lookups in mysql for the things an analyst types verbatim.

Observable values, file hashes, tags and alert uuids already live in indexed columns, so
matching them there is free, never stale, and cannot be fooled by tokenization the way an
embedding is. Every match from this lane is an exact one and is ranked above semantic
matches by the fusion step.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import and_, not_, or_
from sqlalchemy.orm import Query

from saq.database.model import Alert, Observable, ObservableMapping, Tag, TagMapping
from saq.database.pool import get_db
from saq.database.util.index import chunked, tag_key
from saq.search.sparse import identifiers
from saq.search.types import KIND_OBSERVABLE, KIND_TAG, KIND_UUID, LANE_LEXICAL, SearchFilters, SearchHit

HEX_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.IGNORECASE)
UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.IGNORECASE)
UUID_PREFIX_RE = re.compile(r"^[a-f0-9]{8}(-[a-f0-9]{0,4}){0,4}$", re.IGNORECASE)
MIN_TOKEN_LENGTH = 3
MAX_CANDIDATES = 32


@dataclass(frozen=True)
class LexicalCandidates:
    """The literal values pulled out of a query, grouped by what they can match."""

    values: tuple[str, ...] = ()  # observable values and tag names (raw and casefolded variants)
    hashes: tuple[str, ...] = ()  # 32/40/64 hex digests (also matched against observables.sha256)
    uuids: tuple[str, ...] = ()  # full alert uuids
    uuid_prefixes: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not (self.values or self.hashes or self.uuids or self.uuid_prefixes)


def parse_query(query: str) -> LexicalCandidates:
    """Extracts every literal an analyst may be looking for from the query text."""
    query = (query or "").strip()
    if not query:
        return LexicalCandidates()

    raw: list[str] = []
    # the whole query first: "invoice scan.pdf" is a file name with a space in it
    raw.append(query)
    raw.extend(identifiers(query))
    raw.extend(token for token in re.split(r"\s+", query) if len(token) >= MIN_TOKEN_LENGTH)

    values: list[str] = []
    hashes: list[str] = []
    uuids: list[str] = []
    prefixes: list[str] = []
    seen: set[str] = set()

    for token in raw:
        token = token.strip().strip("\"'<>()[]{},;")
        if not token or token in seen:
            continue
        seen.add(token)

        if UUID_RE.match(token):
            uuids.append(token.lower())
            continue

        if UUID_PREFIX_RE.match(token) and len(token) >= 8 and "-" in token:
            prefixes.append(token.lower())

        if HEX_RE.match(token):
            hashes.append(token.lower())

        values.append(token)
        lowered = token.lower()
        if lowered != token:
            values.append(lowered)

    return LexicalCandidates(
        values=tuple(values[:MAX_CANDIDATES]),
        hashes=tuple(hashes[:MAX_CANDIDATES]),
        uuids=tuple(uuids[:MAX_CANDIDATES]),
        uuid_prefixes=tuple(prefixes[:MAX_CANDIDATES]),
    )


def apply_sql_filters(query: Query, filters: SearchFilters) -> Query:
    """Applies SearchFilters to a query over Alert."""
    if filters.insert_date_ranges:
        conditions = [and_(Alert.insert_date >= start, Alert.insert_date <= end) for start, end in filters.insert_date_ranges]
        condition = or_(*conditions)
        query = query.filter(not_(condition) if filters.insert_date_inverted else condition)

    for values, inverted, column in (
        (filters.alert_types, filters.alert_types_inverted, Alert.alert_type),
        (filters.dispositions, filters.dispositions_inverted, Alert.disposition),
        (filters.queues, filters.queues_inverted, Alert.queue),
    ):
        if values:
            condition = column.in_(list(values))
            query = query.filter(not_(condition) if inverted else condition)

    if filters.tags:
        tagged = get_db().query(TagMapping.alert_id).join(Tag, Tag.id == TagMapping.tag_id).filter(Tag.name.in_([tag_key(tag) for tag in filters.tags]))
        condition = Alert.id.in_(tagged)
        query = query.filter(not_(condition) if filters.tags_inverted else condition)

    if filters.locations is not None:
        query = query.filter(Alert.location.in_(list(filters.locations)))

    if filters.exclude_alert_uuids:
        query = query.filter(Alert.uuid.notin_(list(filters.exclude_alert_uuids)))

    return query


def _hit(kind: str, key: str, text: str, title: Optional[str] = None) -> SearchHit:
    return SearchHit(lane=LANE_LEXICAL, kind=kind, key=key, title=title, text=text, score=1.0)


def lexical_search(candidates: LexicalCandidates, filters: SearchFilters, *, limit: int) -> list[tuple[str, list[SearchHit]]]:
    """Alerts matching any candidate exactly, newest first, with one hit per matched thing."""
    if candidates.is_empty():
        return []

    hits: dict[str, list[SearchHit]] = {}
    dates: dict[str, object] = {}

    def record(alert_uuid: str, insert_date, hit: SearchHit) -> None:
        dates[alert_uuid] = insert_date
        existing = hits.setdefault(alert_uuid, [])
        if all(h.key != hit.key for h in existing):
            existing.append(hit)

    db = get_db()

    # observables by value (i_obs_value is a prefix index over the BLOB; equality uses it)
    if candidates.values or candidates.hashes:
        byte_values = list({value.encode("utf-8", errors="ignore") for value in candidates.values})
        for chunk in chunked(byte_values):
            conditions = [Observable.value.in_(chunk)]
            if candidates.hashes:
                conditions.append(Observable.sha256.in_([bytes.fromhex(h) for h in candidates.hashes]))

            query = db.query(Alert.uuid, Alert.insert_date, Observable.type, Observable.value) \
                .join(ObservableMapping, ObservableMapping.alert_id == Alert.id) \
                .join(Observable, Observable.id == ObservableMapping.observable_id) \
                .filter(or_(*conditions))
            query = apply_sql_filters(query, filters).order_by(Alert.insert_date.desc()).limit(limit * 4)
            for alert_uuid, insert_date, observable_type, value in query:
                display = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
                record(alert_uuid, insert_date, _hit(KIND_OBSERVABLE, f"{observable_type}:{display}", display, title=observable_type))

    # tags by name (tags.name is case-insensitive in the database; casefold to match)
    if candidates.values:
        names = list({tag_key(value) for value in candidates.values})
        for chunk in chunked(names):
            query = db.query(Alert.uuid, Alert.insert_date, Tag.name) \
                .join(TagMapping, TagMapping.alert_id == Alert.id) \
                .join(Tag, Tag.id == TagMapping.tag_id) \
                .filter(Tag.name.in_(chunk))
            query = apply_sql_filters(query, filters).order_by(Alert.insert_date.desc()).limit(limit * 4)
            for alert_uuid, insert_date, name in query:
                record(alert_uuid, insert_date, _hit(KIND_TAG, f"tag:{name}", name, title="tag"))

    # alert uuids (exact or prefix)
    if candidates.uuids or candidates.uuid_prefixes:
        conditions = []
        if candidates.uuids:
            conditions.append(Alert.uuid.in_(list(candidates.uuids)))
        conditions.extend(Alert.uuid.like(f"{prefix}%") for prefix in candidates.uuid_prefixes)
        query = db.query(Alert.uuid, Alert.insert_date).filter(or_(*conditions))
        query = apply_sql_filters(query, filters).order_by(Alert.insert_date.desc()).limit(limit)
        for alert_uuid, insert_date in query:
            record(alert_uuid, insert_date, _hit(KIND_UUID, f"uuid:{alert_uuid}", alert_uuid, title="alert uuid"))

    ordered = sorted(hits, key=lambda u: dates.get(u) or datetime.min, reverse=True)
    return [(alert_uuid, hits[alert_uuid]) for alert_uuid in ordered[:limit]]
