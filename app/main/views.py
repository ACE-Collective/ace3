from app.blueprints import main
from flask import redirect, render_template, url_for
from flask_login import current_user, login_required

from aceapi_v2.sync import run_async_with_session
from aceapi_v2.users import service as users_service
from app.user_preferences import get_manage_columns_preference, manage_column_layout

@main.route('/', methods=['GET'])
def index():
    # are we logged in?
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    # default to the manage alerts page
    return redirect(url_for("analysis.manage"))


async def _user_and_held_catalog(session, user_id: int):
    return (
        await users_service.get_user(session, user_id),
        await users_service.list_held_catalog(session, user_id),
    )


@main.route('/preferences', methods=['GET'])
@login_required
def preferences():
    """The analyst's own settings: profile fields they may edit themselves, their durable GUI
    preferences and their API keys. Flask only renders the page; every save is a call from the
    browser to aceapi_v2 (/users/me, /users/me/preferences and /users/me/apikeys)."""
    user, held_catalog = run_async_with_session(_user_and_held_catalog, current_user.id)
    # user:self is what lets the user change their keys; as a scope entry it would grant a key
    # nothing, since those routes refuse every API key
    can_manage_keys = any((e.major, e.minor) == ("user", "self") for e in held_catalog)
    return render_template(
        'preferences.html',
        user=user,
        timezones=users_service.all_timezones(),
        manage_column_layout=manage_column_layout(get_manage_columns_preference()),
        can_manage_keys=can_manage_keys,
        key_catalog=[e.model_dump() for e in held_catalog if (e.major, e.minor) != ("user", "self")],
    )
