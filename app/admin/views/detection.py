import logging
from datetime import datetime

from flask import render_template, request
from flask_login import current_user

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.detection import service
from aceapi_v2.sync import run_async_with_session

EXPIRATION_FORMAT = "%Y-%m-%d %H:%M:%S"


@admin.route("/detection", methods=["GET"])
@require_permission("detection", "read")
def detection_settings():
    # default view shows the observables currently enabled for detection; "all" shows everything
    show = request.args.get("show", "enabled")
    for_detection = None if show == "all" else True
    search = request.args.get("q") or None

    observables = run_async_with_session(
        service.list_detection_observables,
        for_detection=for_detection,
        search=search,
    )
    return render_template(
        "admin/detection.html",
        observables=observables,
        show=show,
        search=search or "",
    )


@admin.route("/detection/toggle", methods=["POST"])
@require_permission("detection", "write")
def detection_toggle():
    observable_id = int(request.form["observable_id"])
    enabled = request.form.get("enabled") == "true"
    detection_context = request.form.get("detection_context")
    if enabled and not detection_context:
        detection_context = f"manually enabled in the admin gui by {current_user}"

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
