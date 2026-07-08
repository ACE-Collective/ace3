"""Observable-detection settings service (ACE API v2).

DB-row-centric management of the ``observables.for_detection`` flag: browse the observables table and
toggle detection / expiration by row id. This is distinct from
``saq/database/util/observable_detection.py``, whose helpers operate on in-memory analysis
``Observable`` objects during alert processing.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from saq.database.model import Observable
from aceapi_v2.detection.schemas import ObservableDetectionRead


def _to_read(obs: Observable) -> ObservableDetectionRead:
    return ObservableDetectionRead(
        id=obs.id,
        type=obs.type,
        value=obs.value.decode("utf8", errors="ignore"),
        for_detection=bool(obs.for_detection),
        expires_on=obs.expires_on,
        enabled_by=obs.enabled_by_user.display_name if obs.enabled_by_user else None,
        detection_context=obs.detection_context,
        batch_id=obs.batch_id,
    )


async def list_detection_observables(
    session: AsyncSession,
    *,
    for_detection: bool | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[ObservableDetectionRead]:
    stmt = select(Observable).options(selectinload(Observable.enabled_by_user))
    if for_detection is not None:
        stmt = stmt.where(Observable.for_detection == for_detection)
    if search:
        stmt = stmt.where(Observable.value.like(b"%" + search.encode("utf8", errors="ignore") + b"%"))
    stmt = stmt.order_by(Observable.id.desc()).limit(limit).offset(offset)

    result = await session.execute(stmt)
    return [_to_read(obs) for obs in result.scalars().all()]


async def _get(session: AsyncSession, observable_id: int) -> Observable | None:
    result = await session.execute(
        select(Observable)
        .options(selectinload(Observable.enabled_by_user))
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
    enabled_by_user_id: int,
    detection_context: str | None = None,
) -> ObservableDetectionRead | None:
    obs = await _get(session, observable_id)
    if obs is None:
        return None

    obs.for_detection = enabled
    if enabled:
        obs.enabled_by = enabled_by_user_id
        if detection_context is not None:
            obs.detection_context = detection_context

    await session.flush()
    # the enabled_by_user relationship was loaded before enabled_by changed; expire it so the
    # re-read reflects the new user rather than the cached value.
    session.expire(obs, ["enabled_by_user"])
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
