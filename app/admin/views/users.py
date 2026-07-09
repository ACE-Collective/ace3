from flask import jsonify, render_template, request

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.sync import run_async_with_session
from aceapi_v2.users import service


@admin.route("/users", methods=["GET"])
@require_permission("user", "read")
def manage_users():
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


@admin.route("/users/details", methods=["GET"])
@require_permission("user", "read")
def get_user_details():
    user_ids_text = request.args.get("user_ids")
    if not user_ids_text:
        return jsonify({"error": "no user ids provided"}), 400

    user_ids = [int(uid) for uid in user_ids_text.split(",")]
    details = run_async_with_session(service.get_users_details, user_ids)

    # keep the same JSON shape the client JS expects (string keys -> user detail dicts)
    return jsonify({str(uid): detail.model_dump() for uid, detail in details.items()})
