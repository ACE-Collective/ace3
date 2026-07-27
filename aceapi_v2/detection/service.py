"""Observable-detection settings service (ACE API v2).

Management of the ``observable_detections`` table: browse, search, add, remove, and set expiration.

The table is deliberately small and separate from ``observables`` (see
:class:`saq.database.model.ObservableDetection`), which is what lets this module search with a plain
``LIKE '%term%'`` and order by ``value`` directly, with no generated sort column and no index
gymnastics.
"""

import math
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from saq.database.model import Observable, ObservableComment, ObservableDetection
from saq.database.util.observable_detection import (
    InvalidDetectionValue,
    default_detection_expiration,
    resolve_detection_identity,
)
from saq.observables.type_hierarchy import get_all_valid_types
from aceapi_v2.detection.schemas import (
    ObservableCommentSummary,
    ObservableDetectionRead,
    DetectionPage,
)

PAGE_SIZE_CHOICES = (25, 50, 100, 200)
DEFAULT_PAGE_SIZE = 50


class DetectionAlreadyExists(Exception):
    """A detection for this type and value is already present."""


def _to_read(detection: ObservableDetection, context: dict | None = None) -> ObservableDetectionRead:
    context = context or {}
    return ObservableDetectionRead(
        id=detection.id,
        type=detection.type,
        value=detection.value,
        expires_on=detection.expires_on,
        detection_context=detection.detection_context,
        batch_id=detection.batch_id,
        created_by=detection.created_by_user.display_name if detection.created_by_user else None,
        created_at=detection.created_at,
        modified_by=detection.modified_by_user.display_name if detection.modified_by_user else None,
        modified_at=detection.modified_at,
        observable_id=context.get("observable_id"),
        fa_hits=context.get("fa_hits"),
        comments=context.get("comments", []),
    )


def _escape_like(term: str) -> str:
    """Escape LIKE metacharacters so a search for '100%' or 'a_b' is a literal substring match."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _search_pattern(search: str) -> str:
    """Builds the LIKE pattern for a search term.

    A term containing '*' is treated as an explicit pattern -- '*' becomes '%' and nothing else is
    added, so an analyst can anchor a search ('evil.*' or '*.ru'). Otherwise the term is escaped and
    wrapped for a plain substring match.
    """
    if "*" in search:
        return _escape_like(search).replace("*", "%")
    return f"%{_escape_like(search)}%"


def _apply_filters(stmt, *, search: str | None, observable_type: str | None):
    if observable_type:
        stmt = stmt.where(ObservableDetection.type == observable_type)
    if search:
        # `value` carries a case-insensitive collation, so this needs no CAST and finds "EXAMPLE"
        # when the analyst types "example". The leading wildcard means a scan, which is fine: this
        # table holds curated detections, not every observable ever seen.
        stmt = stmt.where(ObservableDetection.value.like(_search_pattern(search), escape="\\"))
    return stmt


def clamp_page_size(page_size: int | None) -> int:
    if page_size in PAGE_SIZE_CHOICES:
        return page_size
    return DEFAULT_PAGE_SIZE


async def list_present_types(session: AsyncSession) -> list[str]:
    """Distinct observable types that currently have a detection, for the filter dropdown."""
    result = await session.execute(
        select(ObservableDetection.type).distinct().order_by(ObservableDetection.type))
    return [t for (t,) in result.all()]


def list_all_observable_types() -> list[str]:
    """Every valid observable type, for the create form.

    Read from the type registry rather than the database: a detection may be created for a type that
    has never appeared in an alert. Same source as the /observable_types endpoint -- the configured
    observable_types.yaml plus the Python-registered classes.
    """
    return sorted(get_all_valid_types())


async def count_detections(
    session: AsyncSession,
    *,
    search: str | None = None,
    observable_type: str | None = None,
) -> int:
    stmt = _apply_filters(
        select(func.count()).select_from(ObservableDetection),
        search=search, observable_type=observable_type,
    )
    return int((await session.execute(stmt)).scalar_one())


async def _load_observable_context(session: AsyncSession, detections: list[ObservableDetection]) -> dict:
    """Looks up what the observables index knows about each detection's value.

    Keyed by (type, value_sha256), which is the same shape as the observables i_type_sha256 unique
    key, so this is one indexed lookup for the whole page. Detections whose value has never been
    seen are simply absent from the result.
    """
    if not detections:
        return {}

    keys = {(d.type, d.value_sha256) for d in detections}
    stmt = (
        select(Observable)
        .options(selectinload(Observable.observable_comments).selectinload(ObservableComment.user))
        .where(Observable.sha256.in_({sha256 for (_, sha256) in keys}))
    )
    result = await session.execute(stmt)

    context = {}
    for observable in result.scalars().all():
        key = (observable.type, observable.sha256)
        if key not in keys:
            # a hash can be shared across types; only keep the ones we actually asked for
            continue

        context[key] = {
            "observable_id": observable.id,
            "fa_hits": observable.fa_hits,
            "comments": [
                ObservableCommentSummary(
                    comment=c.comment,
                    user_display_name=c.user.display_name if c.user else "",
                    insert_date=c.insert_date,
                )
                # oldest-first, matching the observable-comments service's ordering
                for c in sorted(observable.observable_comments, key=lambda c: c.insert_date)
            ],
        }

    return context


async def list_detections(
    session: AsyncSession,
    *,
    search: str | None = None,
    observable_type: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> list[ObservableDetectionRead]:
    stmt = _apply_filters(
        select(ObservableDetection).options(
            selectinload(ObservableDetection.created_by_user),
            selectinload(ObservableDetection.modified_by_user),
        ),
        search=search, observable_type=observable_type,
    )
    # grouped by type, alphabetical by value, with `id` as a tiebreaker so pagination is
    # deterministic. `value` is a plain collatable column, so this is an ordinary sort.
    stmt = stmt.order_by(ObservableDetection.type, ObservableDetection.value, ObservableDetection.id)
    stmt = stmt.limit(limit).offset(offset)

    detections = list((await session.execute(stmt)).scalars().all())
    context = await _load_observable_context(session, detections)
    return [_to_read(d, context.get((d.type, d.value_sha256))) for d in detections]


async def get_detection_page(
    session: AsyncSession,
    *,
    search: str | None = None,
    observable_type: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> DetectionPage:
    """A page of detections plus the totals the UI needs. Page numbers are 1-based and clamped."""
    page_size = clamp_page_size(page_size)

    total = await count_detections(session, search=search, observable_type=observable_type)
    total_pages = max(1, math.ceil(total / page_size))
    page = max(1, min(page, total_pages))

    items = await list_detections(
        session,
        search=search, observable_type=observable_type,
        limit=page_size, offset=(page - 1) * page_size,
    )
    return DetectionPage(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages
    )


async def _get(session: AsyncSession, detection_id: int) -> ObservableDetection | None:
    result = await session.execute(
        select(ObservableDetection)
        .options(
            selectinload(ObservableDetection.created_by_user),
            selectinload(ObservableDetection.modified_by_user),
        )
        .where(ObservableDetection.id == detection_id)
    )
    return result.scalar_one_or_none()


async def get_detection(session: AsyncSession, detection_id: int) -> ObservableDetectionRead | None:
    detection = await _get(session, detection_id)
    if detection is None:
        return None

    context = await _load_observable_context(session, [detection])
    return _to_read(detection, context.get((detection.type, detection.value_sha256)))


async def create_detection(
    session: AsyncSession,
    *,
    observable_type: str,
    value: str,
    created_by_user_id: int | None,
    detection_context: str | None = None,
    expires_on: datetime | None = None,
    batch_id: str | None = None,
) -> ObservableDetectionRead:
    """Adds a detection.

    Raises InvalidDetectionValue if the value is not valid for the type (which also normalizes it),
    and DetectionAlreadyExists if one is already present. The observable does not need to exist in
    the observables index -- that is the point of this table.
    """
    identity = resolve_detection_identity(observable_type, value)

    existing = await session.execute(
        select(ObservableDetection.id).where(
            ObservableDetection.type == identity.type,
            ObservableDetection.value_sha256 == identity.value_sha256,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise DetectionAlreadyExists(
            f"a detection already exists for {identity.type} {identity.value}")

    detection = ObservableDetection(
        type=identity.type,
        value=identity.value,
        value_sha256=identity.value_sha256,
        detection_context=detection_context,
        # no explicit expiration falls back to the per-type default from
        # observable_expiration_mappings, which is None (never expires) unless configured
        expires_on=expires_on if expires_on is not None else default_detection_expiration(identity.type),
        batch_id=batch_id,
        created_by=created_by_user_id,
        modified_by=created_by_user_id,
    )
    session.add(detection)
    await session.flush()
    await session.refresh(detection)
    return await get_detection(session, detection.id)


async def delete_detection(session: AsyncSession, detection_id: int) -> bool:
    """Removes a detection. Returns False if it did not exist.

    A row here *is* an active detection, so this is how one is turned off.
    """
    detection = await _get(session, detection_id)
    if detection is None:
        return False

    await session.delete(detection)
    await session.flush()
    return True


async def set_detection_expiration(
    session: AsyncSession,
    detection_id: int,
    expires_on: datetime | None,
    modified_by_user_id: int | None = None,
) -> ObservableDetectionRead | None:
    detection = await _get(session, detection_id)
    if detection is None:
        return None

    detection.expires_on = expires_on
    detection.modified_by = modified_by_user_id
    await session.flush()
    # the relationship was loaded before modified_by changed; expire it so the re-read reflects the
    # new user rather than the cached value.
    session.expire(detection, ["modified_by_user"])
    return await get_detection(session, detection_id)
