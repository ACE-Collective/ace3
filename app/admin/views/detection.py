from flask import render_template, request

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.detection import service
from aceapi_v2.sync import run_async_with_session


def _int_arg(name: str, default: int) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


@admin.route("/detection", methods=["GET"])
@require_permission("detection", "read")
def detection_settings():
    """Render the observable-detection settings page.

    This is the only Flask surface for detection settings. Adding and removing detections and
    adjusting expiration are served by aceapi_v2 and called directly from the page's JavaScript.
    """
    search = request.args.get("q") or None
    observable_type = request.args.get("type") or None
    page = _int_arg("page", 1)
    page_size = service.clamp_page_size(_int_arg("page_size", service.DEFAULT_PAGE_SIZE))

    result = run_async_with_session(
        service.get_detection_page,
        search=search,
        observable_type=observable_type,
        page=page,
        page_size=page_size,
    )
    # the filter dropdown lists only types that actually have a detection; the create form lists
    # every registered type, since a detection can be added for a type never seen before
    present_types = run_async_with_session(service.list_present_types)

    return render_template(
        "admin/detection.html",
        page=result,
        detections=result.items,
        observable_types=present_types,
        all_observable_types=service.list_all_observable_types(),
        selected_type=observable_type or "",
        search=search or "",
        page_size_choices=service.PAGE_SIZE_CHOICES,
    )
