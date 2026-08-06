"""Schemas for the users/roles management API (ACE API v2)."""

from datetime import datetime

from pydantic import BaseModel


class PermissionRead(BaseModel):
    id: int
    major: str
    minor: str
    effect: str
    source: str  # 'user' or 'group:<name>'
    group_id: int | None = None


class GroupPermissionRead(BaseModel):
    id: int
    major: str
    minor: str
    effect: str


class UserRead(BaseModel):
    id: int
    username: str
    display_name: str | None = None
    email: str | None = None
    queue: str | None = None
    enabled: bool
    timezone: str | None = None
    api_key_count: int = 0


class ApiKeyCreated(BaseModel):
    """The plaintext key is returned only at creation time and is never recoverable afterward."""
    key_id: int
    user_id: int
    api_key: str


class ApiKeyScope(BaseModel):
    major: str
    minor: str


class ApiKeyRead(BaseModel):
    """API key metadata for the management UI. Never carries the secret."""
    id: int
    name: str
    inherit_user_scope: bool
    scope: list[ApiKeyScope] = []
    created_at: datetime | None = None
    created_by: int | None = None


class ApiKeyCreate(BaseModel):
    """Request to mint a key. Exactly one of `inherit` or a non-empty `scope` must be set --
    the server rejects both-or-neither, so a restricted key can never silently get full scope."""
    name: str
    inherit: bool = False
    scope: list[ApiKeyScope] = []


class GroupRead(BaseModel):
    id: int
    name: str


class CatalogEntryRead(BaseModel):
    major: str
    minor: str
    description: str | None = None


class UserDetail(BaseModel):
    id: int
    username: str
    display_name: str | None = None
    email: str | None = None
    queue: str | None = None
    timezone: str | None = None
    permissions: list[PermissionRead]
    groups: list[GroupRead]


class ManagementView(BaseModel):
    """Everything the users/roles management page needs, in one payload."""
    users: list[UserRead]
    permissions: dict[int, list[PermissionRead]]
    groups: list[GroupRead]
    group_permissions: dict[int, list[GroupPermissionRead]]
    catalog: list[CatalogEntryRead]


class PermissionInput(BaseModel):
    major: str
    minor: str
    effect: str = "ALLOW"


class UserCreate(BaseModel):
    username: str
    email: str
    display_name: str | None = None
    password: str | None = None
    queue: str = "default"
    timezone: str = "UTC"
    permissions: list[PermissionInput] = []
    groups: list[int] = []


class UserUpdate(BaseModel):
    username: str | None = None
    password: str | None = None
    display_name: str | None = None
    email: str | None = None
    queue: str | None = None
    timezone: str | None = None
    enabled: bool | None = None
    permissions: list[PermissionInput] | None = None
    groups: list[int] | None = None


class GroupCreate(BaseModel):
    name: str


class GroupDelete(BaseModel):
    groups: list[int]


class PermissionGrant(BaseModel):
    major: str
    minor: str
    effect: str = "ALLOW"
    users: list[int] = []
    groups: list[int] = []


class PermissionRevoke(BaseModel):
    users: list[int] = []   # AuthUserPermission ids
    groups: list[int] = []  # AuthGroupPermission ids
