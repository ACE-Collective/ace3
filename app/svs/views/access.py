"""Umbrella access gate for the entire /svs area.

`svs:run_read` grants entry to the area: the SVS nav link and, via this blueprint-level
before_request, every page in it. Enforcing it here rather than per view means a page added later
inherits the gate and cannot forget it. Pages that hand out more layer their own permission on top
(the Test hosts tab needs `svs:admin`; acting on runs needs `svs:run_manage`, which the API enforces).
"""

from flask import abort
from flask_login import current_user, login_required

from app.blueprints import svs
from saq.permissions.logic import user_has_permission


@svs.before_request
@login_required
def require_svs_area_access():
    # @login_required handles the unauthenticated case (redirect to login); by here the user is
    # authenticated, so a missing permission is a genuine 403.
    if not user_has_permission(current_user.id, "svs", "run_read"):
        abort(403)
