from flask import render_template, request

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.sync import run_async_with_session
from aceapi_v2.users import service


@admin.route("/users", methods=["GET"])
@require_permission("user", "read")
def manage_users():
    """Render the users/roles management page.

    This is the only Flask surface for user management. Every mutation (and the per-user detail
    lookup) is served by aceapi_v2 and called directly from the page's JavaScript.
    """
    hide_disabled_users = request.cookies.get("hide_disabled_users", "false") == "true"

    view = run_async_with_session(service.get_management_view, not hide_disabled_users)

    return render_template(
        "admin/manage.html",
        users=view.users,
        permissions=view.permissions,
        auth_groups=view.groups,
        group_permissions=view.group_permissions,
        permission_catalog=[entry.model_dump() for entry in view.catalog],
        timezones=service.all_timezones(),
        hide_disabled_users=hide_disabled_users,
    )
