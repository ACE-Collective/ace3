"""Umbrella access gate for the entire /signatures area.

`signature:read` grants entry to the area: the Signatures nav link, the hub and, via this
blueprint-level before_request, every page in it. Enforcing it here rather than per view means a
page added later inherits the gate and cannot forget it. Pages that hand out more than signature
data layer their own permission on top (downloading YARA QA files needs `signature:download`,
which the API enforces).
"""

from flask import abort
from flask_login import current_user, login_required

from app.blueprints import signatures
from saq.permissions.logic import user_has_permission


@signatures.before_request
@login_required
def require_signatures_area_access():
    # @login_required handles the unauthenticated case (redirect to login); by here the user is
    # authenticated, so a missing permission is a genuine 403.
    if not user_has_permission(current_user.id, "signature", "read"):
        abort(403)
