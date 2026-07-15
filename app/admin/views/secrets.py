from flask import render_template

from app.auth.permissions import require_permission
from app.blueprints import admin
from aceapi_v2.secrets import service
from aceapi_v2.sync import run_async


@admin.route("/secrets", methods=["GET"])
@require_permission("secret", "read")
def manage_secrets():
    """Render the encrypted-secrets management page.

    This is the only Flask surface for secrets. Setting and deleting secret values are served by
    aceapi_v2 and called directly from the page's JavaScript (Flask renders pages only).
    """
    page = run_async(service.get_secrets_page())
    return render_template(
        "admin/secrets.html",
        secrets=page.secrets,
        encryption_unlocked=page.encryption_unlocked,
    )
