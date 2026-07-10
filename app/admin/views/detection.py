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

    This is the only Flask surface for detection settings. Toggling detection and adjusting
    expiration are served by aceapi_v2 and called directly from the page's JavaScript.
    """
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
