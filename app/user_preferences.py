"""Flask-side access to the current user's preferences.

Preferences live in the user_preferences table and are owned by aceapi_v2 (see
aceapi_v2/user_preferences). The GUI pages that render from a preference read it through
the sync bridge here; the pages that CHANGE one call the API directly from the browser.
"""

from flask_login import current_user

from aceapi_v2.sync import run_async_with_session
from aceapi_v2.user_preferences import service as user_preferences_service
from aceapi_v2.user_preferences.schemas import PREFERENCE_KEY_MANAGE_COLUMNS, ManageColumnsPreference
from saq.gui.manage_columns import MANAGE_COLUMNS_BY_ID


def get_manage_columns_preference() -> ManageColumnsPreference:
    """The current user's alert-list column layout, the default if none is stored."""
    preference = run_async_with_session(
        user_preferences_service.get_preference, current_user.id, PREFERENCE_KEY_MANAGE_COLUMNS)
    return ManageColumnsPreference.model_validate(preference.value)


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
