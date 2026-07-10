"""The /admin GUI area.

Only page views live here. Every JSON endpoint the admin pages use is served by aceapi_v2 and
called directly from the browser; Flask renders the pages and nothing else.
"""

from app.admin.views.hub import admin_hub
from app.admin.views.users import manage_users
from app.admin.views.detection import detection_settings

__all__ = [
    'admin_hub',
    'manage_users',
    'detection_settings',
]
