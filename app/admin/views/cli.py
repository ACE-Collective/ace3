from flask import render_template

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.cli import service
from aceapi_v2.cli.schemas import DEFAULT_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS


@admin.route("/cli", methods=["GET"])
@require_permission("cli", "execute")
def cli_console():
    """Render the CLI page. Running a command and following its output are served by aceapi_v2
    (/api/v2/cli) and called directly from the page's JavaScript."""
    return render_template(
        "admin/cli.html",
        nodes=service.list_nodes(),
        default_timeout=DEFAULT_TIMEOUT_SECONDS,
        max_timeout=MAX_TIMEOUT_SECONDS,
    )
