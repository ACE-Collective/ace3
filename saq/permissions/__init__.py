# Group management
from .group import (
    create_auth_group,
    delete_auth_group,
    add_user_to_auth_group,
    delete_user_from_auth_group,
    add_group_permission,
    delete_group_permission,
    get_group_permissions,
    GroupPermission,
)

# User management
from .user import (
    add_user_permission,
    delete_user_permission,
    get_user_permissions,
    UserPermission,
)

# Permission logic
from .logic import user_has_permission, user_has_permission_async

# Permission catalog (authoritative list of enforced permissions)
from .catalog import (
    CatalogEntry,
    PERMISSION_CATALOG,
    CATALOG_PAIRS,
    CATALOG_MAJORS,
    is_grantable,
    sync_permission_catalog,
)

__all__ = [
    # Group management
    "create_auth_group",
    "delete_auth_group",
    "add_user_to_auth_group",
    "delete_user_from_auth_group",
    "add_group_permission",
    "delete_group_permission",
    "get_group_permissions",
    "GroupPermission",
    # User management
    "add_user_permission",
    "delete_user_permission",
    "get_user_permissions",
    "UserPermission",
    # Permission logic
    "user_has_permission",
    "user_has_permission_async",
    # Permission catalog
    "CatalogEntry",
    "PERMISSION_CATALOG",
    "CATALOG_PAIRS",
    "CATALOG_MAJORS",
    "is_grantable",
    "sync_permission_catalog",
]