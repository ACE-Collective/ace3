from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

if TYPE_CHECKING:
    from ..models.catalog_entry_read import CatalogEntryRead
    from ..models.group_read import GroupRead
    from ..models.management_view_group_permissions import (
        ManagementViewGroupPermissions,
    )
    from ..models.management_view_permissions import ManagementViewPermissions
    from ..models.user_read import UserRead


T = TypeVar("T", bound="ManagementView")


@_attrs_define
class ManagementView:
    """Everything the users/roles management page needs, in one payload.

    Attributes:
        users (list[UserRead]):
        permissions (ManagementViewPermissions):
        groups (list[GroupRead]):
        group_permissions (ManagementViewGroupPermissions):
        catalog (list[CatalogEntryRead]):
    """

    users: list[UserRead]
    permissions: ManagementViewPermissions
    groups: list[GroupRead]
    group_permissions: ManagementViewGroupPermissions
    catalog: list[CatalogEntryRead]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        users = []
        for users_item_data in self.users:
            users_item = users_item_data.to_dict()
            users.append(users_item)

        permissions = self.permissions.to_dict()

        groups = []
        for groups_item_data in self.groups:
            groups_item = groups_item_data.to_dict()
            groups.append(groups_item)

        group_permissions = self.group_permissions.to_dict()

        catalog = []
        for catalog_item_data in self.catalog:
            catalog_item = catalog_item_data.to_dict()
            catalog.append(catalog_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "users": users,
                "permissions": permissions,
                "groups": groups,
                "group_permissions": group_permissions,
                "catalog": catalog,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        from ..models.catalog_entry_read import CatalogEntryRead
        from ..models.group_read import GroupRead
        from ..models.management_view_group_permissions import (
            ManagementViewGroupPermissions,
        )
        from ..models.management_view_permissions import ManagementViewPermissions
        from ..models.user_read import UserRead

        d = dict(src_dict)
        users = []
        _users = d.pop("users")
        for users_item_data in _users:
            users_item = UserRead.from_dict(users_item_data)

            users.append(users_item)

        permissions = ManagementViewPermissions.from_dict(d.pop("permissions"))

        groups = []
        _groups = d.pop("groups")
        for groups_item_data in _groups:
            groups_item = GroupRead.from_dict(groups_item_data)

            groups.append(groups_item)

        group_permissions = ManagementViewGroupPermissions.from_dict(
            d.pop("group_permissions")
        )

        catalog = []
        _catalog = d.pop("catalog")
        for catalog_item_data in _catalog:
            catalog_item = CatalogEntryRead.from_dict(catalog_item_data)

            catalog.append(catalog_item)

        management_view = cls(
            users=users,
            permissions=permissions,
            groups=groups,
            group_permissions=group_permissions,
            catalog=catalog,
        )

        management_view.additional_properties = d
        return management_view

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
