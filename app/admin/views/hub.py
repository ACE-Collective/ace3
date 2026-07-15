from flask import current_app, render_template

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
    {
        "endpoint": "admin.manage_secrets",
        "title": "Secrets",
        "description": "Set and manage encrypted config secrets (API keys, passwords).",
        "major": "secret",
        "minor": "read",
    },
]


@admin.route("/")
def admin_hub():
    # Auth and the admin:read umbrella gate are enforced by the blueprint before_request (see
    # app/admin/views/access.py), so no per-view decorator is needed here.
    modules = [m for m in ADMIN_MODULES if m["endpoint"] in current_app.view_functions]
    return render_template("admin/hub.html", admin_modules=modules)
