"""Schemas for the users/roles management API (ACE API v2)."""

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
