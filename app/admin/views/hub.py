from flask import current_app, render_template
from flask_login import login_required

from app.blueprints import admin

# Candidate admin modules shown on the hub landing page. A tile renders only when its endpoint is
# registered (so the hub stays valid as modules are added) AND the current user holds the required
# permission (enforced in the template via has_permission).
ADMIN_MODULES = [
    {
        "endpoint": "admin.detection_settings",
        "title": "Observables",
        "description": "View and manage which observables are enabled for detection.",
        "major": "detection",
        "minor": "read",
    },
    {
        "endpoint": "admin.manage_users",
        "title": "Users & Roles",
        "description": "Manage users, auth groups, and permission grants.",
        "major": "user",
        "minor": "read",
    },
]


@admin.route("/")
@login_required
def admin_hub():
    modules = [m for m in ADMIN_MODULES if m["endpoint"] in current_app.view_functions]
    return render_template("admin/hub.html", admin_modules=modules)
