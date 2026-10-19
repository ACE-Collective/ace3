"""Flask-side access to the current user's preferences.

Preferences live in the user_preferences table and are owned by aceapi_v2 (see
aceapi_v2/user_preferences). The GUI pages that render from a preference read it here (the
theme from the request session, the rest through the sync bridge); the pages that CHANGE
one call the API directly from the browser.
"""

from flask_login import current_user

from aceapi_v2.sync import run_async_with_session
from aceapi_v2.user_preferences import service as user_preferences_service
from aceapi_v2.user_preferences.schemas import (
    PREFERENCE_KEY_MANAGE_COLUMNS,
    PREFERENCE_KEY_THEME,
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


def get_theme_preference() -> ThemePreference:
    """The current user's GUI theme, "system" for an anonymous visitor or if none is stored."""
    if not current_user.is_authenticated:
        return ThemePreference()

    # every page reads this, so it uses the request's sync session (as has_permission() does)
    # rather than a round-trip through the background loop, and a database failure falls
    # back to the default: the theme is cosmetic, and the 500 page reads it too
    try:
        row = (
            get_db().query(UserPreference)
            .filter(UserPreference.user_id == current_user.id, UserPreference.key == PREFERENCE_KEY_THEME)
            .one_or_none()
        )
    except Exception as e:
        log_loop_exception(e, f"reading the theme preference of user {current_user.id}")
        return ThemePreference()

    return ThemePreference.model_validate(user_preferences_service.to_read(PREFERENCE_KEY_THEME, row).value)


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
