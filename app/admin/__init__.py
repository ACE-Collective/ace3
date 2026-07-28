"""The /admin GUI area.

Only page views live here. Every JSON endpoint the admin pages use is served by aceapi_v2 and
called directly from the browser; Flask renders the pages and nothing else.
"""

# Imported first so its before_request guard is registered on the blueprint: `admin:read` gates the
# whole area, and every page below layers its own permission on top.
from app.admin.views import access  # noqa: F401
from app.admin.views.hub import admin_hub
from app.admin.views.users import manage_users
from app.admin.views.detection import detection_settings
from app.admin.views.secrets import manage_secrets

__all__ = [
    'admin_hub',
    'manage_users',
    'detection_settings',
    'manage_secrets',
]
