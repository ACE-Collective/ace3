"""Saved filter service for ACE API v2.

Every function here returns Pydantic models, never ORM rows.

Saved filters belong to a screen (saq/gui/filter_screens.py). Everything that lists, creates
or bounds rows takes the screen explicitly; a row addressed by uuid carries its own. Filters
are validated against their screen's entry model, so a pydantic ValidationError from here means
the caller sent a filter that screen does not support.
"""

import json
import logging
import uuid as uuid_module

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aceapi_v2.saved_filters.schemas import (
    FilterEntryBase,
    QuickFilterOrder,
    SavedFilterCreate,
    SavedFilterRead,
    SavedFilterUpdate,
    ScratchFilterWrite,
)
from saq.database.model import SavedFilter
from saq.gui.filter_screens import ALERTS_SCREEN, FILTER_SCREENS, FilterScreen, get_filter_screen

logger = logging.getLogger(__name__)

KIND_NAMED = "named"
KIND_WORKING = "working"
KIND_TEMP = "temp"
SCRATCH_KINDS = (KIND_WORKING, KIND_TEMP)

# What a brand-new analyst gets on the alert screen. Stored as RELATIVE tokens so the windows
# stay correct forever -- that is the whole point of the relative-time work.
DEFAULT_ALERT_SAVED_FILTERS = (
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

# screen name -> the saved filters a user starts with on that screen
DEFAULT_SAVED_FILTERS = {
    ALERTS_SCREEN.name: DEFAULT_ALERT_SAVED_FILTERS,
}


class SavedFilterNameConflict(Exception):
    """This user already has a saved filter with that name."""


def _to_read(row: SavedFilter) -> SavedFilterRead:
    # validated with the row's own screen, which also normalizes legacy values; a row whose
    # screen is no longer registered is still readable as plain entries
    screen = FILTER_SCREENS.get(row.screen)
    entry_model = screen.entry_model if screen else FilterEntryBase
    return SavedFilterRead(
        uuid=row.uuid,
        screen=row.screen,
        kind=row.kind,
        name=row.name,
        description=row.description,
        filters=[entry_model.model_validate(entry) for entry in json.loads(row.filters_json)],
        quick_filter_order=row.quick_filter_order,
        quick_filter_indicator=row.quick_filter_indicator,
        owner_id=row.user_id,
        owner_display_name=(row.user.display_name or row.user.username) if row.user else "unknown",
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _dump(filters, screen: FilterScreen) -> str:
    """Validate a filter list against its screen and serialize it for storage."""
    return json.dumps([entry.model_dump() for entry in screen.validate_entries(filters)])


async def _get_row(session: AsyncSession, filter_uuid: str) -> SavedFilter | None:
    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.uuid == filter_uuid)
        .options(selectinload(SavedFilter.user))
    )
    return result.scalar_one_or_none()


async def get_saved_filter_screen(session: AsyncSession, filter_uuid: str) -> str | None:
    """The screen a row belongs to, whoever owns it, or None for an unknown row. Used to check
    the screen's permission before the row is touched."""
    result = await session.execute(select(SavedFilter.screen).where(SavedFilter.uuid == filter_uuid))
    return result.scalar_one_or_none()


async def _owned_row(session: AsyncSession, filter_uuid: str, user_id: int) -> SavedFilter | None:
    row = await _get_row(session, filter_uuid)
    if row is None:
        return None
    if row.user_id != user_id:
        raise PermissionError(f"saved filter {filter_uuid} does not belong to user {user_id}")

    return row


async def get_saved_filters_for_user(
    session: AsyncSession, user_id: int, *, screen: str
) -> list[SavedFilterRead]:
    """The caller's named filters on a screen, pinned ones first in badge order then by name.

    Read-only on purpose: the polled refresh endpoint calls this every 30 seconds, so
    seeding is a separate explicit call (ensure_default_saved_filters)."""
    get_filter_screen(screen)
    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.user_id == user_id,
               SavedFilter.screen == screen,
               SavedFilter.kind == KIND_NAMED)
        .options(selectinload(SavedFilter.user))
        .order_by(SavedFilter.quick_filter_order.is_(None),
                  SavedFilter.quick_filter_order,
                  SavedFilter.name)
    )
    return [_to_read(row) for row in result.scalars().all()]


async def get_saved_filter(
    session: AsyncSession, filter_uuid: str, user_id: int, *, screen: str | None = None
) -> SavedFilterRead | None:
    """Read one of the caller's own rows. Returns None for unknown or someone else's --
    there is no cross-user read, because sharing does not go through the database. With a
    screen, a row of another screen is None too: a caller that is about to apply the filter
    to its own screen must never be handed another screen's filter names."""
    row = await _get_row(session, filter_uuid)
    if row is None or row.user_id != user_id:
        return None
    if screen is not None and row.screen != screen:
        return None

    return _to_read(row)


async def create_saved_filter(
    session: AsyncSession, user_id: int, data: SavedFilterCreate, *, screen: str
) -> SavedFilterRead:
    filter_screen = get_filter_screen(screen)
    filters_json = _dump(data.filters, filter_screen)

    quick_filter_order = None
    if data.quick_filter:
        quick_filter_order = await _next_quick_filter_order(session, user_id, screen)

    row = SavedFilter(
        uuid=str(uuid_module.uuid4()),
        user_id=user_id,
        screen=screen,
        kind=KIND_NAMED,
        name=data.name,
        description=data.description,
        filters_json=filters_json,
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

    # validated against the row's own screen, before anything on the row changes
    filters_json = _dump(data.filters, get_filter_screen(row.screen)) if data.filters is not None else None

    if data.name is not None:
        row.name = data.name
    if data.description is not None:
        row.description = data.description
    if filters_json is not None:
        row.filters_json = filters_json
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


async def _next_quick_filter_order(session: AsyncSession, user_id: int, screen: str) -> int:
    result = await session.execute(
        select(SavedFilter.quick_filter_order)
        .where(SavedFilter.user_id == user_id,
               SavedFilter.screen == screen,
               SavedFilter.kind == KIND_NAMED,
               SavedFilter.quick_filter_order.is_not(None))
        .order_by(SavedFilter.quick_filter_order.desc())
        .limit(1)
    )
    highest = result.scalar_one_or_none()
    return 0 if highest is None else highest + 1


async def set_quick_filters(
    session: AsyncSession, user_id: int, order: QuickFilterOrder, *, screen: str
) -> list[SavedFilterRead]:
    """Set quick-filter membership AND order on one screen in one atomic call.

    Orders are always renumbered densely 0..N-1 rather than preserved, so repeated
    pin/unpin cycles cannot leave gaps that make the badge order look arbitrary."""
    get_filter_screen(screen)
    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.user_id == user_id,
               SavedFilter.screen == screen,
               SavedFilter.kind == KIND_NAMED)
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
    return await get_saved_filters_for_user(session, user_id, screen=screen)


async def upsert_scratch_filter(
    session: AsyncSession, user_id: int, kind: str, data: ScratchFilterWrite, *, screen: str
) -> SavedFilterRead:
    """Replace the caller's singleton `working` or `temp` row on a screen, creating it if
    needed."""

    #Singleton-ness is enforced here rather than by a constraint: MySQL has no partial
    # unique index, the only racer is the same user's own session, and a stray extra row is
    # harmless. Bounding it here is what keeps this table from growing per edit.

    if kind not in SCRATCH_KINDS:
        raise ValueError(f"invalid scratch kind {kind!r}")

    filters_json = _dump(data.filters, get_filter_screen(screen))

    result = await session.execute(
        select(SavedFilter)
        .where(SavedFilter.user_id == user_id,
               SavedFilter.screen == screen,
               SavedFilter.kind == kind)
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
            screen=screen,
            kind=kind,
            name=None,
            description=data.label,
            filters_json=filters_json,
        )
        session.add(row)
        await session.flush()
        await session.refresh(row, attribute_names=["created_at", "updated_at"])
        await session.execute(
            select(SavedFilter).where(SavedFilter.id == row.id).options(selectinload(SavedFilter.user)))
    else:
        row.filters_json = filters_json
        row.description = data.label
        await session.flush()
        await session.refresh(row, attribute_names=["updated_at"])

    return _to_read(row)


async def ensure_default_saved_filters(session: AsyncSession, user_id: int, *, screen: str) -> None:
    """Give an analyst new to a screen that screen's default quick filters (the alert screen:
    Last 24h / Last 7d).

    Seeds only when the user has NO saved_filters rows of ANY kind on that screen, and the
    caller must invoke it before the working row is created (see
    _ensure_manage_session_defaults).
    """
    filter_screen = get_filter_screen(screen)
    defaults = DEFAULT_SAVED_FILTERS.get(screen, ())
    if not defaults:
        return

    result = await session.execute(
        select(SavedFilter.id)
        .where(SavedFilter.user_id == user_id, SavedFilter.screen == screen)
        .limit(1)
    )
    if result.scalar_one_or_none() is not None:
        return

    for position, spec in enumerate(defaults):
        session.add(SavedFilter(
            uuid=str(uuid_module.uuid4()),
            user_id=user_id,
            screen=screen,
            kind=KIND_NAMED,
            name=spec["name"],
            description=spec["description"],
            filters_json=_dump(spec["filters"], filter_screen),
            quick_filter_order=position,
            quick_filter_indicator=False,
        ))

    try:
        await session.flush()
    except IntegrityError:
        # another request for this same user seeded first -- theirs is as good as ours
        await session.rollback()
        logger.debug("default saved filters for user %s were seeded concurrently", user_id)
