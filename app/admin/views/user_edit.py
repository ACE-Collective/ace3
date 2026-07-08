from flask import flash, jsonify, redirect, request, url_for
from flask_login import current_user

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.sync import run_async_with_session
from aceapi_v2.users import service
from aceapi_v2.users.schemas import PermissionInput, UserUpdate


def _permission_inputs(raw: list[dict]) -> list[PermissionInput]:
    return [PermissionInput(**p) for p in raw]


@admin.route("/users/add", methods=["POST"])
@require_permission("user", "write")
def add_user():
    user = request.get_json()
    run_async_with_session(
        service.create_user,
        username=user["username"],
        email=user["email"],
        display_name=user.get("display_name"),
        password=user.get("password"),
        queue=user.get("queue", "default"),
        timezone=user.get("timezone", "UTC"),
        permissions=_permission_inputs(user.get("permissions", [])),
        groups=user.get("groups", []),
        created_by=current_user.id,
    )
    return jsonify({"success": "User added successfully"}), 200


@admin.route("/users/edit", methods=["POST"])
@require_permission("user", "write")
def edit_users():
    users = request.get_json()  # {user_id: {changes...}}
    changes = {int(uid): UserUpdate(**details) for uid, details in users.items()}
    try:
        run_async_with_session(service.update_users, changes, current_user.id)
    except service.UserNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify({"success": "Users updated successfully"}), 200


@admin.route("/groups/add", methods=["POST"])
@require_permission("user", "write")
def add_auth_group():
    name = (request.form.get("add_auth_group_name") or "").strip()
    if not name:
        return jsonify({"error": "no name provided"}), 400
    run_async_with_session(service.create_auth_group, name)
    flash("permission group added")
    return redirect(url_for("admin.manage_users"))


@admin.route("/groups/delete", methods=["POST"])
@require_permission("user", "write")
def delete_auth_groups():
    group_ids = (request.get_json() or {}).get("groups", [])
    if not group_ids:
        return jsonify({"error": "no group ids provided"}), 400
    run_async_with_session(service.delete_auth_groups, group_ids)
    return jsonify({"success": "permission groups deleted"}), 200


@admin.route("/permissions/add", methods=["POST"])
@require_permission("user", "write")
def add_permission():
    permission = request.get_json()
    run_async_with_session(
        service.grant_permission,
        perm=PermissionInput(
            major=permission["major"], minor=permission["minor"], effect=permission["effect"]
        ),
        user_ids=permission.get("users", []),
        group_ids=permission.get("groups", []),
        actor_id=current_user.id,
    )
    return jsonify({"success": "Permission added successfully"}), 200


@admin.route("/permissions/delete", methods=["POST"])
@require_permission("user", "write")
def delete_permission():
    permissions = request.get_json()
    run_async_with_session(
        service.revoke_permissions,
        user_permission_ids=permissions.get("users", []),
        group_permission_ids=permissions.get("groups", []),
    )
    return jsonify({"success": "Permission deleted successfully"}), 200
