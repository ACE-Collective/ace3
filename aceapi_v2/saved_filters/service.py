"""Saved filter service for ACE API v2.

Every function here returns Pydantic models, never ORM rows. 
"""

import json
import logging
import uuid as uuid_module

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aceapi_v2.saved_filters.schemas import (
    FilterEntry,
    QuickFilterOrder,
    SavedFilterCreate,
    SavedFilterRead,
    SavedFilterUpdate,
    ScratchFilterWrite,
)
from saq.database.model import SavedFilter

logger = logging.getLogger(__name__)

KIND_NAMED = "named"
KIND_WORKING = "working"
KIND_TEMP = "temp"
SCRATCH_KINDS = (KIND_WORKING, KIND_TEMP)

# What a brand-new analyst gets. Stored as RELATIVE tokens so the windows stay correct
# forever -- that is the whole point of the relative-time work.
DEFAULT_SAVED_FILTERS = (
    {
        "name": "Last 24h",
        "description": "Alerts in your queue from the last 24 hours",
        "filters": [
            {"name": "Queue", "inverted": False, "values": ["$USER_QUEUE"]},
            {"name": "Alert Date", "inverted": False, "values": ["-24h"]},
        ],
    },
    {
        "name": "Last 7d",
        "description": "Alerts in your queue from the last 7 days",
        "filters": [
            {"name": "Queue", "inverted": False, "values": ["$USER_QUEUE"]},
            {"name": "Alert Date", "inverted": False, "values": ["-7d"]},
        ],
    },
)


class SavedFilterNameConflict(Exception):
    """This user already has a saved filter with that name."""


def _to_read(row: SavedFilter) -> SavedFilterRead:
    return SavedFilterRead(
        uuid=row.uuid,
        kind=row.kind,
        name=row.name,
        description=row.description,
        filters=[FilterEntry.model_validate(entry) for entry in json.loads(row.filters_json)],
        quick_filter_order=row.quick_filter_order,
        quick_filter_indicator=row.quick_filter_indicator,
        owner_id=row.user_id,
        owner_display_name=(row.user.display_name or row.user.username) if row.user else "unknown",
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _dump(filters) -> str:
    """Serialize a filter list for storage."""
    payload = []
    for entry in filters or []:
        if isinstance(entry, FilterEntry):
            payload.append(entry.model_dump())
        else:
            payload.append(FilterEntry.model_validate(entry).model_dump())

    return json.dumps(payload)


async def _get_row(session: AsyncSession, filter_uuid: str) -> SavedFilter | None:
    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.uuid == filter_uuid)
        .options(selectinload(SavedFilter.user))
    )
    return result.scalar_one_or_none()


async def _owned_row(session: AsyncSession, filter_uuid: str, user_id: int) -> SavedFilter | None:
    row = await _get_row(session, filter_uuid)
    if row is None:
        return None
    if row.user_id != user_id:
        raise PermissionError(f"saved filter {filter_uuid} does not belong to user {user_id}")

    return row


async def get_saved_filters_for_user(
    session: AsyncSession, user_id: int
) -> list[SavedFilterRead]:
    """The caller's named filters, pinned ones first in badge order then by name.

    Read-only on purpose: the polled refresh endpoint calls this every 30 seconds, so
    seeding is a separate explicit call (ensure_default_saved_filters)."""
    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.user_id == user_id, SavedFilter.kind == KIND_NAMED)
        .options(selectinload(SavedFilter.user))
        .order_by(SavedFilter.quick_filter_order.is_(None),
                  SavedFilter.quick_filter_order,
                  SavedFilter.name)
    )
    return [_to_read(row) for row in result.scalars().all()]


async def get_saved_filter(
    session: AsyncSession, filter_uuid: str, user_id: int
) -> SavedFilterRead | None:
    """Read one of the caller's own rows. Returns None for unknown or someone else's --
    there is no cross-user read, because sharing does not go through the database."""
    row = await _get_row(session, filter_uuid)
    if row is None or row.user_id != user_id:
        return None

    return _to_read(row)


async def create_saved_filter(
    session: AsyncSession, user_id: int, data: SavedFilterCreate
) -> SavedFilterRead:
    quick_filter_order = None
    if data.quick_filter:
        quick_filter_order = await _next_quick_filter_order(session, user_id)

    row = SavedFilter(
        uuid=str(uuid_module.uuid4()),
        user_id=user_id,
        kind=KIND_NAMED,
        name=data.name,
        description=data.description,
        filters_json=_dump(data.filters),
        quick_filter_order=quick_filter_order,
        quick_filter_indicator=data.quick_filter_indicator,
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError as e:
        await session.rollback()
        raise SavedFilterNameConflict(f"a saved filter named {data.name!r} already exists") from e

    await session.refresh(row, attribute_names=["created_at", "updated_at"])
    await session.execute(select(SavedFilter).where(SavedFilter.id == row.id).options(selectinload(SavedFilter.user)))
    return _to_read(row)


async def update_saved_filter(
    session: AsyncSession, filter_uuid: str, user_id: int, data: SavedFilterUpdate
) -> SavedFilterRead | None:
    row = await _owned_row(session, filter_uuid, user_id)
    if row is None:
        return None

    if data.name is not None:
        row.name = data.name
    if data.description is not None:
        row.description = data.description
    if data.filters is not None:
        row.filters_json = _dump(data.filters)
    if data.quick_filter_indicator is not None:
        row.quick_filter_indicator = data.quick_filter_indicator

    try:
        await session.flush()
    except IntegrityError as e:
        await session.rollback()
        raise SavedFilterNameConflict(f"a saved filter named {data.name!r} already exists") from e

    # the UPDATE bumped updated_at server-side; without this the response reports the value the
    # row carried before this very call (SavedFilter.updated_at is server_onupdate).
    await session.refresh(row, attribute_names=["updated_at"])
    return _to_read(row)


async def delete_saved_filter(session: AsyncSession, filter_uuid: str, user_id: int) -> bool:
    row = await _owned_row(session, filter_uuid, user_id)
    if row is None:
        return False

    await session.delete(row)
    await session.flush()
    return True


async def _next_quick_filter_order(session: AsyncSession, user_id: int) -> int:
    result = await session.execute(
        select(SavedFilter.quick_filter_order)
        .where(SavedFilter.user_id == user_id,
               SavedFilter.kind == KIND_NAMED,
               SavedFilter.quick_filter_order.is_not(None))
        .order_by(SavedFilter.quick_filter_order.desc())
        .limit(1)
    )
    highest = result.scalar_one_or_none()
    return 0 if highest is None else highest + 1


async def set_quick_filters(
    session: AsyncSession, user_id: int, order: QuickFilterOrder
) -> list[SavedFilterRead]:
    """Set quick-filter membership AND order in one atomic call.

    Orders are always renumbered densely 0..N-1 rather than preserved, so repeated
    pin/unpin cycles cannot leave gaps that make the badge order look arbitrary."""
    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.user_id == user_id, SavedFilter.kind == KIND_NAMED)
        .options(selectinload(SavedFilter.user))
    )
    rows = {row.uuid: row for row in result.scalars().all()}

    unknown = [u for u in order.filter_uuids if u not in rows]
    if unknown:
        raise ValueError(f"unknown or unowned saved filter(s): {', '.join(unknown)}")

    pinned = set(order.filter_uuids)
    for position, filter_uuid in enumerate(order.filter_uuids):
        rows[filter_uuid].quick_filter_order = position
    for filter_uuid, row in rows.items():
        if filter_uuid not in pinned:
            row.quick_filter_order = None

    await session.flush()
    # this re-SELECT is not just for ordering: it also re-reads the updated_at that the flush
    # above expired on every row it touched. Sorting `rows` in Python instead would serve the
    # pre-UPDATE timestamps and make two identical calls return different bodies.
    return await get_saved_filters_for_user(session, user_id)


async def upsert_scratch_filter(
    session: AsyncSession, user_id: int, kind: str, data: ScratchFilterWrite
) -> SavedFilterRead:
    """Replace the caller's singleton `working` or `temp` row, creating it if needed."""

    #Singleton-ness is enforced here rather than by a constraint: MySQL has no partial
    # unique index, the only racer is the same user's own session, and a stray extra row is
    # harmless. Bounding it here is what keeps this table from growing per edit.

    if kind not in SCRATCH_KINDS:
        raise ValueError(f"invalid scratch kind {kind!r}")

    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.user_id == user_id, SavedFilter.kind == kind)
        .options(selectinload(SavedFilter.user))
        .order_by(SavedFilter.id)
    )
    rows = list(result.scalars().all())
    row = rows[0] if rows else None

    # clean up any duplicate that lost a race previously
    for extra in rows[1:]:
        await session.delete(extra)

    if row is None:
        row = SavedFilter(
            uuid=str(uuid_module.uuid4()),
            user_id=user_id,
            kind=kind,
            name=None,
            description=data.label,
            filters_json=_dump(data.filters),
        )
        session.add(row)
        await session.flush()
        await session.refresh(row, attribute_names=["created_at", "updated_at"])
        await session.execute(
            select(SavedFilter).where(SavedFilter.id == row.id).options(selectinload(SavedFilter.user)))
    else:
        row.filters_json = _dump(data.filters)
        row.description = data.label
        await session.flush()
        await session.refresh(row, attribute_names=["updated_at"])

    return _to_read(row)


async def ensure_default_saved_filters(session: AsyncSession, user_id: int) -> None:
    """Give a brand-new analyst the Last 24h / Last 7d quick filters.

    Seeds only when the user has NO saved_filters rows of ANY kind, and the caller must
    invoke it before the working row is created (see _ensure_manage_session_defaults).
    """
    result = await session.execute(
        select(SavedFilter.id).where(SavedFilter.user_id == user_id).limit(1)
    )
    if result.scalar_one_or_none() is not None:
        return

    for position, spec in enumerate(DEFAULT_SAVED_FILTERS):
        session.add(SavedFilter(
            uuid=str(uuid_module.uuid4()),
            user_id=user_id,
            kind=KIND_NAMED,
            name=spec["name"],
            description=spec["description"],
            filters_json=_dump(spec["filters"]),
            quick_filter_order=position,
            quick_filter_indicator=False,
        ))

    try:
        await session.flush()
    except IntegrityError:
        # another request for this same user seeded first -- theirs is as good as ours
        await session.rollback()
        logger.debug("default saved filters for user %s were seeded concurrently", user_id)
