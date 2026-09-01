"""Observable service for ACE API v2."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.observables.schemas import (
    EventMembership,
    LookupPair,
    ObservableLookupResponse,
    ObservableLookupResult,
    RecentAlertSummary,
)
from saq.constants import ANALYSIS_TYPE_FAQUEUE
from saq.database.model import (
    Alert,
    Event,
    EventMapping,
    EventStatus,
    Observable as DBObservable,
    ObservableMapping,
)
from saq.database.util.index import CHUNK_SIZE, ObservableKey, chunked, observable_key
from saq.database.util.observable_detection import (
    InvalidDetectionValue,
    resolve_observable_identity,
)


async def observable_is_interesting(
    session: AsyncSession, observable_type: str, sha256_bytes: bytes
) -> bool:
    """Returns True if the observable is marked as interesting in the database."""
    result = await session.execute(
        select(DBObservable.is_interesting).where(
            DBObservable.type == observable_type,
            DBObservable.sha256 == sha256_bytes,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return False
    return bool(row)


async def set_observable_interesting(
    session: AsyncSession,
    observable_type: str,
    observable_value: str,
    is_interesting: bool,
) -> None:
    """Sets or clears the is_interesting flag on an observable.

    Raises InvalidDetectionValue if the value is not valid for the type.
    """
    identity = resolve_observable_identity(observable_type, observable_value)

    result = await session.execute(
        select(DBObservable).where(
            DBObservable.type == identity.type,
            DBObservable.sha256 == identity.value_sha256,
        )
    )
    db_observable = result.scalar_one_or_none()

    if db_observable is None:
        if not is_interesting:
            return
        db_observable = DBObservable(
            type=identity.type,
            sha256=identity.value_sha256,
            value=identity.value.encode("utf8"),
            is_interesting=True,
        )
        session.add(db_observable)
    else:
        db_observable.is_interesting = is_interesting

    await session.flush()


async def get_interesting_observables_by_hashes(
    session: AsyncSession, sha256_list: list[bytes]
) -> list[DBObservable]:
    """Returns all interesting DB observables matching any of the given sha256 hashes."""
    if not sha256_list:
        return []

    result = await session.execute(
        select(DBObservable).where(
            DBObservable.sha256.in_(sha256_list),
            DBObservable.is_interesting == True,
        )
    )
    return list(result.scalars().all())


# batch prevalence lookup
#
# Alerts with alert_type 'faqueue' are excluded everywhere an alert is counted or listed, matching
# saq/database/database_observable.py. Unlike that module's DispositionHistory, the histogram here
# keeps OPEN and UNKNOWN so that total_alert_count == sum(disposition_counts.values()).
#
# No cap on per-observable work: the aggregate is a covering range scan of the observable_mapping
# PK plus PK probes into alerts (the same shape the GUI runs per alert render), and an exact
# prevalence count is the point of the endpoint. recent_alert_limit=0 skips the one statement that
# needs a per-observable sort.


@dataclass
class _ResolvedPair:
    """One normalized request pair."""
    type: str
    value: str
    value_sha256: bytes


@dataclass
class _AlertAggregate:
    total_alert_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    disposition_counts: dict[str, int] = field(default_factory=dict)


async def lookup_observables(
    session: AsyncSession,
    *,
    pairs: list[LookupPair],
    recent_alert_limit: int,
    exclude_alert_uuids: list[str],
    since: datetime | None,
) -> ObservableLookupResponse:
    """Batch observable prevalence lookup. See ObservableLookupRequest/-Result for semantics."""
    if since is not None and since.tzinfo is not None:
        # alerts.insert_date is a naive TIMESTAMP; compare in the same terms
        since = since.astimezone(timezone.utc).replace(tzinfo=None)

    resolved, index_to_key, errors = _normalize_pairs(pairs)
    id_to_key = await _resolve_observable_ids(session, list(resolved.values()))
    observable_ids = list(id_to_key)

    exclude_alert_ids: list[int] = []
    if exclude_alert_uuids and observable_ids:
        exclude_alert_ids = await _resolve_exclude_alert_ids(session, exclude_alert_uuids)

    aggregates: dict[int, _AlertAggregate] = {}
    recent: dict[int, list[RecentAlertSummary]] = {}
    events: dict[int, list[EventMembership]] = {}
    if observable_ids:
        aggregates = await _load_alert_aggregates(session, observable_ids, exclude_alert_ids, since)
        if recent_alert_limit > 0:
            recent = await _load_recent_alerts(
                session, observable_ids, recent_alert_limit, exclude_alert_ids, since)
        events = await _load_event_memberships(session, observable_ids, exclude_alert_ids)

    key_to_id = {key: observable_id for observable_id, key in id_to_key.items()}
    results: list[ObservableLookupResult] = []
    for index, pair in enumerate(pairs):
        if index in errors:
            results.append(ObservableLookupResult(index=index, type=pair.type, error=errors[index]))
            continue

        identity = resolved[index_to_key[index]]
        observable_id = key_to_id.get(index_to_key[index])
        if observable_id is None:
            results.append(ObservableLookupResult(
                index=index, type=identity.type, value=identity.value, found=False))
            continue

        aggregate = aggregates.get(observable_id, _AlertAggregate())
        results.append(ObservableLookupResult(
            index=index,
            type=identity.type,
            value=identity.value,
            found=True,
            total_alert_count=aggregate.total_alert_count,
            first_seen=aggregate.first_seen,
            last_seen=aggregate.last_seen,
            disposition_counts=aggregate.disposition_counts,
            recent_alerts=recent.get(observable_id, []),
            events=events.get(observable_id, []),
        ))

    return ObservableLookupResponse(results=results)


def _normalize_pairs(
    pairs: list[LookupPair],
) -> tuple[dict[ObservableKey, _ResolvedPair], dict[int, ObservableKey], dict[int, str]]:
    """Resolves each pair to its stored identity, collecting per-index errors instead of raising."""
    resolved: dict[ObservableKey, _ResolvedPair] = {}
    index_to_key: dict[int, ObservableKey] = {}
    errors: dict[int, str] = {}
    for index, pair in enumerate(pairs):
        try:
            identity = resolve_observable_identity(pair.type, pair.value)
        except InvalidDetectionValue as e:
            errors[index] = str(e)
            continue

        key = observable_key(identity.type, identity.value_sha256)
        if key not in resolved:
            resolved[key] = _ResolvedPair(
                type=identity.type, value=identity.value, value_sha256=identity.value_sha256)
        index_to_key[index] = key

    return resolved, index_to_key, errors


async def _resolve_observable_ids(
    session: AsyncSession, identities: list[_ResolvedPair]
) -> dict[int, ObservableKey]:
    """Maps observables.id to the casefolded lookup key for every identity present in the index."""
    id_to_key: dict[int, ObservableKey] = {}
    for chunk in chunked(identities, CHUNK_SIZE):
        result = await session.execute(
            select(DBObservable.id, DBObservable.type, DBObservable.sha256).where(
                tuple_(DBObservable.type, DBObservable.sha256).in_(
                    [(identity.type, identity.value_sha256) for identity in chunk])))
        for observable_id, observable_type, sha256 in result:
            id_to_key[observable_id] = observable_key(observable_type, sha256)
    return id_to_key


async def _resolve_exclude_alert_ids(session: AsyncSession, uuids: list[str]) -> list[int]:
    result = await session.execute(select(Alert.id).where(Alert.uuid.in_(uuids)))
    return list(result.scalars())


def _alert_predicates(
    observable_ids: list[int], exclude_alert_ids: list[int], since: datetime | None
) -> list:
    predicates = [
        ObservableMapping.observable_id.in_(observable_ids),
        Alert.alert_type != ANALYSIS_TYPE_FAQUEUE,
    ]
    if exclude_alert_ids:
        predicates.append(ObservableMapping.alert_id.notin_(exclude_alert_ids))
    if since is not None:
        predicates.append(Alert.insert_date >= since)
    return predicates


async def _load_alert_aggregates(
    session: AsyncSession,
    observable_ids: list[int],
    exclude_alert_ids: list[int],
    since: datetime | None,
) -> dict[int, _AlertAggregate]:
    """One grouped statement per chunk: histogram, total, and first/last seen together."""
    aggregates: dict[int, _AlertAggregate] = {}
    for chunk in chunked(observable_ids, CHUNK_SIZE):
        result = await session.execute(
            select(
                ObservableMapping.observable_id,
                Alert.disposition,
                func.count(),
                func.min(Alert.insert_date),
                func.max(Alert.insert_date),
            )
            .join(Alert, Alert.id == ObservableMapping.alert_id)
            .where(*_alert_predicates(chunk, exclude_alert_ids, since))
            .group_by(ObservableMapping.observable_id, Alert.disposition))
        for observable_id, disposition, count, first_seen, last_seen in result:
            aggregate = aggregates.setdefault(observable_id, _AlertAggregate())
            aggregate.total_alert_count += count
            aggregate.disposition_counts[disposition] = count
            if aggregate.first_seen is None or first_seen < aggregate.first_seen:
                aggregate.first_seen = first_seen
            if aggregate.last_seen is None or last_seen > aggregate.last_seen:
                aggregate.last_seen = last_seen
    return aggregates


async def _load_recent_alerts(
    session: AsyncSession,
    observable_ids: list[int],
    limit: int,
    exclude_alert_ids: list[int],
    since: datetime | None,
) -> dict[int, list[RecentAlertSummary]]:
    """The newest `limit` alerts per observable via one windowed statement per chunk."""
    recent: dict[int, list[RecentAlertSummary]] = {}
    for chunk in chunked(observable_ids, CHUNK_SIZE):
        row_number = (
            func.row_number()
            .over(
                partition_by=ObservableMapping.observable_id,
                order_by=(Alert.insert_date.desc(), Alert.id.desc()))
            .label("row_number"))
        ranked = (
            select(
                ObservableMapping.observable_id,
                Alert.uuid,
                Alert.disposition,
                Alert.insert_date,
                row_number,
            )
            .join(Alert, Alert.id == ObservableMapping.alert_id)
            .where(*_alert_predicates(chunk, exclude_alert_ids, since))
            .subquery())
        result = await session.execute(
            select(ranked.c.observable_id, ranked.c.uuid, ranked.c.disposition, ranked.c.insert_date)
            .where(ranked.c.row_number <= limit)
            .order_by(ranked.c.observable_id, ranked.c.row_number))
        for observable_id, alert_uuid, disposition, insert_date in result:
            recent.setdefault(observable_id, []).append(RecentAlertSummary(
                uuid=alert_uuid, disposition=disposition, insert_date=insert_date))
    return recent


async def _load_event_memberships(
    session: AsyncSession,
    observable_ids: list[int],
    exclude_alert_ids: list[int],
) -> dict[int, list[EventMembership]]:
    """Distinct events over every matched alert. Never joins alerts (no faqueue/since filtering:
    a faqueue alert is never mapped into an event, and an old event membership is still worth
    surfacing)."""
    events: dict[int, list[EventMembership]] = {}
    for chunk in chunked(observable_ids, CHUNK_SIZE):
        predicates = [ObservableMapping.observable_id.in_(chunk)]
        if exclude_alert_ids:
            predicates.append(ObservableMapping.alert_id.notin_(exclude_alert_ids))
        result = await session.execute(
            select(
                ObservableMapping.observable_id,
                Event.id,
                Event.uuid,
                Event.name,
                Event.creation_date,
                EventStatus.value,
            )
            .distinct()
            .join(EventMapping, EventMapping.alert_id == ObservableMapping.alert_id)
            .join(Event, Event.id == EventMapping.event_id)
            .join(EventStatus, EventStatus.id == Event.status_id)
            .where(*predicates)
            .order_by(ObservableMapping.observable_id, Event.creation_date.desc(), Event.id.desc()))
        for observable_id, event_id, event_uuid, name, creation_date, status in result:
            events.setdefault(observable_id, []).append(EventMembership(
                id=event_id, uuid=event_uuid, name=name, creation_date=creation_date, status=status))
    return events
