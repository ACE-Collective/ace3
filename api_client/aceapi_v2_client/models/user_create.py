from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.permission_input import PermissionInput


T = TypeVar("T", bound="UserCreate")


@_attrs_define
class UserCreate:
    """
    Attributes:
        username (str):
        email (str):
        display_name (None | str | Unset):
        password (None | str | Unset):
        queue (str | Unset):  Default: 'default'.
        timezone (str | Unset):  Default: 'UTC'.
        permissions (list[PermissionInput] | Unset):
        groups (list[int] | Unset):
    """

    username: str
    email: str
    display_name: None | str | Unset = UNSET
    password: None | str | Unset = UNSET
    queue: str | Unset = "default"
    timezone: str | Unset = "UTC"
    permissions: list[PermissionInput] | Unset = UNSET
    groups: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        username = self.username

        email = self.email

        display_name: None | str | Unset
        if isinstance(self.display_name, Unset):
            display_name = UNSET
        else:
            display_name = self.display_name

        password: None | str | Unset
        if isinstance(self.password, Unset):
            password = UNSET
        else:
            password = self.password

        queue = self.queue

        timezone = self.timezone

        permissions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.permissions, Unset):
            permissions = []
            for permissions_item_data in self.permissions:
                permissions_item = permissions_item_data.to_dict()
                permissions.append(permissions_item)

        groups: list[int] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "username": username,
                "email": email,
            }
        )
        if display_name is not UNSET:
            field_dict["display_name"] = display_name
        if password is not UNSET:
            field_dict["password"] = password
        if queue is not UNSET:
            field_dict["queue"] = queue
        if timezone is not UNSET:
            field_dict["timezone"] = timezone
        if permissions is not UNSET:
            field_dict["permissions"] = permissions
        if groups is not UNSET:
            field_dict["groups"] = groups

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        from ..models.permission_input import PermissionInput

        d = dict(src_dict)
        username = d.pop("username")

        email = d.pop("email")

        def _parse_display_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        display_name = _parse_display_name(d.pop("display_name", UNSET))

        def _parse_password(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        password = _parse_password(d.pop("password", UNSET))

        queue = d.pop("queue", UNSET)

        timezone = d.pop("timezone", UNSET)

        _permissions = d.pop("permissions", UNSET)
        permissions: list[PermissionInput] | Unset = UNSET
        if _permissions is not UNSET:
            permissions = []
            for permissions_item_data in _permissions:
                permissions_item = PermissionInput.from_dict(permissions_item_data)

                permissions.append(permissions_item)

        groups = cast(list[int], d.pop("groups", UNSET))

        user_create = cls(
            username=username,
            email=email,
            display_name=display_name,
            password=password,
            queue=queue,
            timezone=timezone,
            permissions=permissions,
            groups=groups,
        )

        user_create.additional_properties = d
        return user_create

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
