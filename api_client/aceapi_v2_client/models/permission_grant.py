from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="PermissionGrant")


@_attrs_define
class PermissionGrant:
    """
    Attributes:
        major (str):
        minor (str):
        effect (str | Unset):  Default: 'ALLOW'.
        users (list[int] | Unset):
        groups (list[int] | Unset):
    """

    major: str
    minor: str
    effect: str | Unset = "ALLOW"
    users: list[int] | Unset = UNSET
    groups: list[int] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        major = self.major

        minor = self.minor

        effect = self.effect

        users: list[int] | Unset = UNSET
        if not isinstance(self.users, Unset):
            users = self.users

        groups: list[int] | Unset = UNSET
        if not isinstance(self.groups, Unset):
            groups = self.groups

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "major": major,
                "minor": minor,
            }
        )
        if effect is not UNSET:
            field_dict["effect"] = effect
        if users is not UNSET:
            field_dict["users"] = users
        if groups is not UNSET:
            field_dict["groups"] = groups

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        major = d.pop("major")

        minor = d.pop("minor")

        effect = d.pop("effect", UNSET)

        users = cast(list[int], d.pop("users", UNSET))

        groups = cast(list[int], d.pop("groups", UNSET))

        permission_grant = cls(
            major=major,
            minor=minor,
            effect=effect,
            users=users,
            groups=groups,
        )

        permission_grant.additional_properties = d
        return permission_grant

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
