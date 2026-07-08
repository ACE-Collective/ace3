from app.admin.views.hub import admin_hub
from app.admin.views.users import manage_users, get_user_details
from app.admin.views.user_edit import (
    add_user,
    edit_users,
    add_auth_group,
    delete_auth_groups,
    add_permission,
    delete_permission,
)
from app.admin.views.detection import (
    detection_settings,
    detection_toggle,
    detection_expiration,
)

__all__ = [
    'admin_hub',
    'manage_users',
    'get_user_details',
    'add_user',
    'edit_users',
    'add_auth_group',
    'delete_auth_groups',
    'add_permission',
    'delete_permission',
    'detection_settings',
    'detection_toggle',
    'detection_expiration',
]
