"""Observable-detection settings service (ACE API v2).

DB-row-centric management of the ``observables.for_detection`` flag: browse the observables table and
toggle detection / expiration by row id. This is distinct from
``saq/database/util/observable_detection.py``, whose helpers operate on in-memory analysis
``Observable`` objects during alert processing.
"""

import math
from datetime import datetime

from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from saq.database.model import Observable
from aceapi_v2.detection.schemas import ObservableDetectionRead, ObservablePage

# Offset pagination is appropriate at this table's scale (~4e5 rows): with the
# i_obs_for_detection_id covering index the filtered view is an index lookup, and even a deep offset
# only skips index entries. Revisit keyset pagination if observables grows by ~2 orders of magnitude.
PAGE_SIZE_CHOICES = (25, 50, 100, 200)
DEFAULT_PAGE_SIZE = 50


def _to_read(obs: Observable) -> ObservableDetectionRead:
    return ObservableDetectionRead(
        id=obs.id,
        type=obs.type,
        value=obs.value.decode("utf8", errors="ignore"),
        for_detection=bool(obs.for_detection),
        expires_on=obs.expires_on,
        detection_modified_by=obs.detection_modified_by_user.display_name if obs.detection_modified_by_user else None,
        detection_context=obs.detection_context,
        batch_id=obs.batch_id,
    )


def _escape_like(term: str) -> str:
    """Escape LIKE metacharacters so a search for '100%' or 'a_b' is a literal substring match."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _apply_filters(stmt, *, for_detection: bool | None, search: str | None, observable_type: str | None):
    if for_detection is not None:
        stmt = stmt.where(Observable.for_detection == for_detection)
    if observable_type:
        stmt = stmt.where(Observable.type == observable_type)
    if search:
        # `value` is a BLOB (binary, no collation), so LIKE against it compares bytes and is
        # case-SENSITIVE. Cast to CHAR so the comparison uses utf8mb4's case-insensitive collation --
        # a search for "EXAMPLE" should find "example". We cast rather than search the value_sort
        # generated column because that column is only a 512-char prefix and would silently miss
        # substrings inside long URLs.
        #
        # NOTE: this is a full scan either way -- a leading wildcard cannot use i_obs_value (a
        # 767-byte prefix index). Narrowing by type and/or the enabled set is what keeps it bounded.
        pattern = f"%{_escape_like(search)}%"
        stmt = stmt.where(cast(Observable.value, String).like(pattern, escape="\\"))
    return stmt


def clamp_page_size(page_size: int | None) -> int:
    if page_size in PAGE_SIZE_CHOICES:
        return page_size
    return DEFAULT_PAGE_SIZE


async def list_observable_types(session: AsyncSession) -> list[str]:
    """Distinct observable types present, for the filter dropdown (served by i_obs_type)."""
    result = await session.execute(select(Observable.type).distinct().order_by(Observable.type))
    return [t for (t,) in result.all()]


async def count_detection_observables(
    session: AsyncSession,
    *,
    for_detection: bool | None = None,
    search: str | None = None,
    observable_type: str | None = None,
) -> int:
    stmt = _apply_filters(
        select(func.count()).select_from(Observable),
        for_detection=for_detection, search=search, observable_type=observable_type,
    )
    return int((await session.execute(stmt)).scalar_one())


async def list_detection_observables(
    session: AsyncSession,
    *,
    for_detection: bool | None = None,
    search: str | None = None,
    observable_type: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> list[ObservableDetectionRead]:
    stmt = _apply_filters(
        select(Observable).options(selectinload(Observable.detection_modified_by_user)),
        for_detection=for_detection, search=search, observable_type=observable_type,
    )
    # Grouped by type, alphabetical by value, with `id` as a tiebreaker so rows sharing a value_sort
    # prefix paginate deterministically. Served by i_obs_type_value_sort_id /
    # i_obs_fd_type_value_sort_id with no filesort -- see the value_sort column comment on the model.
    stmt = stmt.order_by(Observable.type, Observable.value_sort, Observable.id)
    stmt = stmt.limit(limit).offset(offset)

    result = await session.execute(stmt)
    return [_to_read(obs) for obs in result.scalars().all()]


async def get_detection_page(
    session: AsyncSession,
    *,
    for_detection: bool | None = None,
    search: str | None = None,
    observable_type: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> ObservablePage:
    """A page of observables plus the totals the UI needs. Page numbers are 1-based and clamped."""
    page_size = clamp_page_size(page_size)

    total = await count_detection_observables(
        session, for_detection=for_detection, search=search, observable_type=observable_type
    )
    total_pages = max(1, math.ceil(total / page_size))
    page = max(1, min(page, total_pages))

    items = await list_detection_observables(
        session,
        for_detection=for_detection, search=search, observable_type=observable_type,
        limit=page_size, offset=(page - 1) * page_size,
    )
    return ObservablePage(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages
    )


async def _get(session: AsyncSession, observable_id: int) -> Observable | None:
    result = await session.execute(
        select(Observable)
        .options(selectinload(Observable.detection_modified_by_user))
        .where(Observable.id == observable_id)
    )
    return result.scalar_one_or_none()


async def get_detection_observable(session: AsyncSession, observable_id: int) -> ObservableDetectionRead | None:
    obs = await _get(session, observable_id)
    return _to_read(obs) if obs is not None else None


async def set_observable_for_detection(
    session: AsyncSession,
    observable_id: int,
    enabled: bool,
    detection_modified_by_user_id: int,
    detection_context: str | None = None,
) -> ObservableDetectionRead | None:
    obs = await _get(session, observable_id)
    if obs is None:
        return None

    # Both enabling and disabling are detection-status changes, so both record who made the change
    # and why. Disabling also clears expires_on: an expiration only governs an *enabled* detection,
    # and a stale one would be silently inherited on re-enable, excluding the observable from the
    # detection cache (see _get_for_detect_observables_by_type) while the UI claims it is enabled.
    obs.for_detection = enabled
    obs.detection_modified_by = detection_modified_by_user_id
    if detection_context is not None:
        obs.detection_context = detection_context
    if not enabled:
        obs.expires_on = None

    await session.flush()
    # the relationship was loaded before detection_modified_by changed; expire it so the re-read
    # reflects the new user rather than the cached value.
    session.expire(obs, ["detection_modified_by_user"])
    return await get_detection_observable(session, observable_id)


async def set_observable_expiration(
    session: AsyncSession,
    observable_id: int,
    expires_on: datetime | None,
) -> ObservableDetectionRead | None:
    obs = await _get(session, observable_id)
    if obs is None:
        return None

    obs.expires_on = expires_on
    await session.flush()
    return _to_read(obs)
