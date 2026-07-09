import logging
from datetime import datetime

from flask import render_template, request
from flask_login import current_user

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.detection import service
from aceapi_v2.sync import run_async_with_session

EXPIRATION_FORMAT = "%Y-%m-%d %H:%M:%S"


def _int_arg(name: str, default: int) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


@admin.route("/detection", methods=["GET"])
@require_permission("detection", "read")
def detection_settings():
    # default view shows the observables currently enabled for detection; "all" shows everything
    show = request.args.get("show", "enabled")
    for_detection = None if show == "all" else True
    search = request.args.get("q") or None
    observable_type = request.args.get("type") or None
    page = _int_arg("page", 1)
    page_size = service.clamp_page_size(_int_arg("page_size", service.DEFAULT_PAGE_SIZE))

    result = run_async_with_session(
        service.get_detection_page,
        for_detection=for_detection,
        search=search,
        observable_type=observable_type,
        page=page,
        page_size=page_size,
    )
    observable_types = run_async_with_session(service.list_observable_types)

    return render_template(
        "admin/detection.html",
        page=result,
        observables=result.items,
        observable_types=observable_types,
        selected_type=observable_type or "",
        show=show,
        search=search or "",
        page_size_choices=service.PAGE_SIZE_CHOICES,
    )


@admin.route("/detection/toggle", methods=["POST"])
@require_permission("detection", "write")
def detection_toggle():
    observable_id = int(request.form["observable_id"])
    enabled = request.form.get("enabled") == "true"
    detection_context = request.form.get("detection_context")
    if not detection_context:
        action = "enabled" if enabled else "disabled"
        detection_context = f"manually {action} in the admin gui by {current_user}"

    result = run_async_with_session(
        service.set_observable_for_detection,
        observable_id,
        enabled,
        current_user.id,
        detection_context,
    )
    if result is None:
        return "Error: observable not found", 404

    logging.info(
        "AUDIT: %s %s observable id=%s for detection",
        current_user, "enabled" if enabled else "disabled", observable_id,
    )
    return ("", 204)


@admin.route("/detection/expiration", methods=["POST"])
@require_permission("detection", "write")
def detection_expiration():
    observable_id = int(request.form["observable_id"])

    expires_on = None
    if not request.form.get("never_expire"):
        raw = request.form.get("expires_on")
        if raw:
            expires_on = datetime.strptime(raw, EXPIRATION_FORMAT)

    result = run_async_with_session(
        service.set_observable_expiration, observable_id, expires_on
    )
    if result is None:
        return "Error: observable not found", 404

    logging.info("AUDIT: %s set expiration for observable id=%s to %s", current_user, observable_id, expires_on)
    return ("", 204)
