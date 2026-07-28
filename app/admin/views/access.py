"""Umbrella access gate for the entire /admin area.

`admin:read` is the single permission that grants entry to the admin area. It gates the Admin nav
link and the hub, and -- via this blueprint-level before_request -- every admin route. Individual
pages layer their own permission on top (e.g. the users page also requires `user:read`), so
`admin:read` is necessary but not sufficient to use any given module.

Enforcing it here rather than as a per-view decorator means a newly added admin page inherits the
umbrella gate automatically and cannot forget it.
"""

from flask import abort
from flask_login import current_user, login_required

from app.blueprints import admin
from saq.permissions.logic import user_has_permission


@admin.before_request
@login_required
def require_admin_area_access():
    # @login_required handles the unauthenticated case (redirect to login); by here the user is
    # authenticated, so a missing permission is a genuine 403.
    if not user_has_permission(current_user.id, "admin", "read"):
        abort(403)
