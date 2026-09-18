"""The lexical lane: exact lookups in mysql for the things an analyst asked for by name.

Observable values, tags and alert uuids already live in indexed columns, so matching them
there is free, never stale, and cannot be fooled by tokenization the way an embedding is.
Every match from this lane is an exact one and is ranked above semantic matches by the fusion
step.

What this lane looks for comes from the query language (`saq/search/syntax.py`) and nothing
else. A literal is only searched for when the analyst wrote it as a field term.

Observables are matched on `(type, sha256)`, the `i_type_sha256` unique key, with the value
normalized by the observable's own class first (`resolve_observable_identity`).
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import and_, not_, or_, tuple_
from sqlalchemy.orm import Query

from saq.database.model import Alert, Observable, ObservableMapping, Tag, TagMapping
from saq.database.pool import get_db
from saq.database.util.index import chunked, tag_key
from saq.database.util.observable_detection import (
    InvalidDetectionValue,
    resolve_observable_identity,
)
from saq.search.syntax import (
    FIELD_ALERT_UUID,
    FIELD_OBSERVABLE,
    FIELD_TAG,
    UUID_RE,
    parse_search_query,
)
from saq.search.types import KIND_OBSERVABLE, KIND_TAG, KIND_UUID, LANE_LEXICAL, SearchFilters, SearchHit


@dataclass(frozen=True)
class LexicalCandidates:
    """The literals the analyst named, in the form each lookup needs.

    Observables are already resolved to their normalized `(type, value, sha256)` identity here
    rather than in the SQL, so the caller pays the observable-class normalization once.
    """

    # (type, value, sha256) -- value is kept only so a hit can be labelled without a round trip
    observables: tuple = ()
    tags: tuple = ()            # casefolded, matching the tags.name collation
    uuids: tuple = ()
    uuid_prefixes: tuple = ()

    def is_empty(self) -> bool:
        return not (self.observables or self.tags or self.uuids or self.uuid_prefixes)


def candidates_from_terms(terms) -> LexicalCandidates:
    """Collects the exact field terms of a parsed query into one set of lookups."""
    observables: list = []
    tags: list = []
    uuids: list = []
    prefixes: list = []

    for term in terms or ():
        if term.field == FIELD_OBSERVABLE:
            for observable_type, observable_value in term.values:
                try:
                    # The parser already normalized these, and normalization is idempotent;
                    # resolving again is what lets a caller hand-build a FieldTerm. A value
                    # that is impossible for its type was already reported by the parser --
                    # skipping it here must never turn into matching everything.
                    identity = resolve_observable_identity(observable_type, observable_value)
                except InvalidDetectionValue:
                    continue
                observables.append((identity.type, identity.value, identity.value_sha256))
        elif term.field == FIELD_TAG:
            tags.extend(tag_key(value) for value in term.values)
        elif term.field == FIELD_ALERT_UUID:
            for value in term.values:
                (uuids if UUID_RE.match(value) else prefixes).append(value.lower())

    return LexicalCandidates(
        observables=tuple(dict.fromkeys(observables)),
        tags=tuple(dict.fromkeys(tags)),
        uuids=tuple(dict.fromkeys(uuids)),
        uuid_prefixes=tuple(dict.fromkeys(prefixes)),
    )


def parse_query(query: str) -> LexicalCandidates:
    """The lookups a raw query string asks for. Convenience for callers that have only text."""
    return candidates_from_terms(parse_search_query(query).exact)


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


def _hit(kind: str, key: str, text: str, title=None) -> SearchHit:
    return SearchHit(lane=LANE_LEXICAL, kind=kind, key=key, title=title, text=text, score=1.0)


def lexical_search(candidates: LexicalCandidates, filters: SearchFilters, *, limit: int) -> list:
    """Alerts matching any candidate exactly, newest first, with one hit per matched thing."""
    if candidates.is_empty():
        return []

    hits: dict = {}
    dates: dict = {}

    def record(alert_uuid: str, insert_date, hit: SearchHit) -> None:
        dates[alert_uuid] = insert_date
        existing = hits.setdefault(alert_uuid, [])
        if all(h.key != hit.key for h in existing):
            existing.append(hit)

    db = get_db()

    # observables by (type, sha256): an exact prefix of the i_type_sha256 unique key, so the
    # row-constructor IN becomes one index seek per pair
    if candidates.observables:
        keys = [(observable_type, sha256) for observable_type, _, sha256 in candidates.observables]
        for chunk in chunked(keys):
            query = db.query(Alert.uuid, Alert.insert_date, Observable.type, Observable.value) \
                .join(ObservableMapping, ObservableMapping.alert_id == Alert.id) \
                .join(Observable, Observable.id == ObservableMapping.observable_id) \
                .filter(tuple_(Observable.type, Observable.sha256).in_(chunk))
            query = apply_sql_filters(query, filters).order_by(Alert.insert_date.desc()).limit(limit * 4)
            for alert_uuid, insert_date, observable_type, value in query:
                display = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
                record(alert_uuid, insert_date, _hit(KIND_OBSERVABLE, f"{observable_type}:{display}", display, title=observable_type))

    # tags by name (tags.name is case-insensitive in the database; casefold to match)
    if candidates.tags:
        for chunk in chunked(list(candidates.tags)):
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
