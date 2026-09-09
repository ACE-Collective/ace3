"""User preference service for ACE API v2.

Every function here returns Pydantic models, never ORM rows (see the note on
SavedFilterRead). A stored value is re-validated through its key's model on every read, so
a stale row -- one that names a column id a later release removed -- is repaired on the way
out rather than breaking the page that reads it.
"""

import json
import logging

from pydantic import BaseModel, ValidationError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.user_preferences.schemas import PREFERENCE_SCHEMAS, PreferenceRead, PreferencesRead
from saq.database.model import UserPreference

logger = logging.getLogger(__name__)


class UnknownPreferenceKey(KeyError):
    """No preference is registered under that key."""


def _schema_for(key: str) -> type[BaseModel]:
    try:
        return PREFERENCE_SCHEMAS[key]
    except KeyError:
        raise UnknownPreferenceKey(key) from None


def _to_read(key: str, row: UserPreference | None) -> PreferenceRead:
    schema = _schema_for(key)
    if row is None:
        return PreferenceRead(key=key, value=schema().model_dump(), updated_at=None, is_default=True)

    try:
        value = schema.model_validate(json.loads(row.value_json))
    except (ValueError, ValidationError) as e:
        # a stored value this release cannot read: fall back to the default rather than
        # take the page down, and say so once in the log
        logger.warning("user %s preference %s is unreadable (%s); using the default", row.user_id, key, e)
        return PreferenceRead(key=key, value=schema().model_dump(), updated_at=row.updated_at, is_default=True)

    return PreferenceRead(key=key, value=value.model_dump(), updated_at=row.updated_at, is_default=False)


async def _get_row(session: AsyncSession, user_id: int, key: str) -> UserPreference | None:
    result = await session.execute(
        select(UserPreference).where(UserPreference.user_id == user_id, UserPreference.key == key)
    )
    return result.scalar_one_or_none()


async def get_preferences(session: AsyncSession, user_id: int) -> PreferencesRead:
    """Every registered preference for this user, defaults filled in for the missing ones."""
    result = await session.execute(select(UserPreference).where(UserPreference.user_id == user_id))
    rows = {row.key: row for row in result.scalars().all()}
    # a row under a key this release no longer registers is simply not reported
    return PreferencesRead(data={key: _to_read(key, rows.get(key)) for key in PREFERENCE_SCHEMAS})


async def get_preference(session: AsyncSession, user_id: int, key: str) -> PreferenceRead:
    """One preference for this user, the default if nothing is stored. Raises
    UnknownPreferenceKey for a key that is not registered."""
    _schema_for(key)
    return _to_read(key, await _get_row(session, user_id, key))


async def set_preference(session: AsyncSession, user_id: int, key: str, value: dict) -> PreferenceRead:
    """Replace this user's stored value for `key` with `value`, validated and normalized
    through the key's model. Raises UnknownPreferenceKey or pydantic.ValidationError."""
    normalized = _schema_for(key).model_validate(value)
    row = await _get_row(session, user_id, key)
    if row is None:
        row = UserPreference(user_id=user_id, key=key)
        session.add(row)

    row.value_json = json.dumps(normalized.model_dump())
    await session.flush()
    # server_onupdate leaves updated_at expired, and the async session cannot lazy-load it
    await session.refresh(row, attribute_names=["updated_at"])
    return _to_read(key, row)


async def reset_preference(session: AsyncSession, user_id: int, key: str) -> PreferenceRead:
    """Delete this user's stored value for `key` so the default applies again. Returns the
    default. Raises UnknownPreferenceKey."""
    _schema_for(key)
    await session.execute(
        delete(UserPreference).where(UserPreference.user_id == user_id, UserPreference.key == key)
    )
    await session.flush()
    return _to_read(key, None)
