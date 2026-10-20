from flask import abort, render_template
from flask_login import current_user

from app.blueprints import svs
from saq.permissions.logic import user_has_permission
from saq.svs.hosts import PLATFORMS


@svs.route("/test-hosts", methods=["GET"])
def test_hosts():
    # the hosts runs may target (docs/SVS_RUNS.md, *Test hosts*); a shell over
    # /api/v2/svs/test-hosts, which needs svs:admin to change one, and so does this tab
    if not user_has_permission(current_user.id, "svs", "admin"):
        abort(403)
    return render_template("svs/test_hosts.html", platforms=PLATFORMS)
