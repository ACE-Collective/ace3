"""Access gate for the /help area: any logged-in user may read the guides.

The guides describe screens that have their own permissions; reading about a screen grants nothing
on it, so the area asks only that the user is logged in.
"""

from flask_login import login_required

from app.blueprints import help_pages


@help_pages.before_request
@login_required
def require_login():
    pass
