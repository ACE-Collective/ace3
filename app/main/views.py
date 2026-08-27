from app.blueprints import main
from flask import redirect, url_for
from flask_login import current_user

@main.route('/', methods=['GET'])
def index():
    # are we logged in?
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    # default to the manage alerts page
    return redirect(url_for("analysis.manage"))
