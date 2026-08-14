from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="PermissionRevoke")


@_attrs_define
class PermissionRevoke:
    """
    Attributes:
        users (list[int] | Unset):
        groups (list[int] | Unset):
    """

    users: list[int] | Unset = UNSET
    groups: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        users: list[int] | Unset = UNSET
        if not isinstance(self.users, Unset):
            users = self.users

        groups: list[int] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if users is not UNSET:
            field_dict["users"] = users
        if groups is not UNSET:
            field_dict["groups"] = groups

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        users = cast(list[int], d.pop("users", UNSET))

        groups = cast(list[int], d.pop("groups", UNSET))

        permission_revoke = cls(
            users=users,
            groups=groups,
        )

        permission_revoke.additional_properties = d
        return permission_revoke

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
