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


@main.route('/preferences', methods=['GET'])
@login_required
def preferences():
    """The analyst's own settings: profile fields they may edit themselves and their
    durable GUI preferences. Flask only renders the page; every save is a call from the
    browser to aceapi_v2 (/users/me and /users/me/preferences)."""
    return render_template(
        'preferences.html',
        user=run_async_with_session(users_service.get_user, current_user.id),
        timezones=users_service.all_timezones(),
        manage_column_layout=manage_column_layout(get_manage_columns_preference()),
    )
