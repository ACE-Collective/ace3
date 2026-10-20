"""Flask-side access to the current user's preferences.

Preferences live in the user_preferences table and are owned by aceapi_v2 (see
aceapi_v2/user_preferences). The GUI pages that render from a preference read it here (the
theme and the alert page sections from the request session, the rest through the sync
bridge); the pages that CHANGE one call the API directly from the browser.
"""

from typing import TypeVar

from flask_login import current_user
from pydantic import BaseModel

from aceapi_v2.sync import run_async_with_session
from aceapi_v2.user_preferences import service as user_preferences_service
from aceapi_v2.user_preferences.schemas import (
    PREFERENCE_KEY_ALERT_SECTIONS,
    PREFERENCE_KEY_MANAGE_COLUMNS,
    PREFERENCE_KEY_THEME,
    AlertSectionsPreference,
    ManageColumnsPreference,
    ThemePreference,
)
from saq.database.model import UserPreference
from saq.database.pool import get_db
from saq.error.reporting import log_loop_exception
from saq.gui.manage_columns import MANAGE_COLUMNS_BY_ID


def get_manage_columns_preference() -> ManageColumnsPreference:
    """The current user's alert-list column layout, the default if none is stored."""
    preference = run_async_with_session(
        user_preferences_service.get_preference, current_user.id, PREFERENCE_KEY_MANAGE_COLUMNS)
    return ManageColumnsPreference.model_validate(preference.value)


PreferenceT = TypeVar("PreferenceT", bound=BaseModel)


def _read_cosmetic_preference(key: str, model: type[PreferenceT]) -> PreferenceT:
    """The current user's value for a preference that only changes how a page looks, the default
    for an anonymous visitor or if none is stored.

    It uses the request's sync session (as has_permission() does) rather than a round-trip
    through the background loop, and a database failure falls back to the default: the page
    must still render, and the 500 page reads the theme too."""
    if not current_user.is_authenticated:
        return model()

    try:
        row = (
            get_db().query(UserPreference)
            .filter(UserPreference.user_id == current_user.id, UserPreference.key == key)
            .one_or_none()
        )
    except Exception as e:
        log_loop_exception(e, f"reading the {key} preference of user {current_user.id}")
        return model()

    return model.model_validate(user_preferences_service.to_read(key, row).value)


def get_theme_preference() -> ThemePreference:
    """The current user's GUI theme, "system" for an anonymous visitor or if none is stored."""
    return _read_cosmetic_preference(PREFERENCE_KEY_THEME, ThemePreference)


def get_alert_sections_preference() -> AlertSectionsPreference:
    """Which alert page sections the current user has chosen to start open or collapsed."""
    return _read_cosmetic_preference(PREFERENCE_KEY_ALERT_SECTIONS, AlertSectionsPreference)


def manage_column_layout(preference: ManageColumnsPreference) -> list[dict]:
    """Every column in the preference's order with its visibility, for the column chooser:
    [{id, label, required, hidden}, ...]."""
    return [
        {
            "id": column_id,
            "label": MANAGE_COLUMNS_BY_ID[column_id].label,
            "required": MANAGE_COLUMNS_BY_ID[column_id].required,
            "hidden": column_id in preference.hidden,
        }
        for column_id in preference.order
    ]
