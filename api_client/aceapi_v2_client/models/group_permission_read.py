from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

T = TypeVar("T", bound="GroupPermissionRead")


@_attrs_define
class GroupPermissionRead:
    """
    Attributes:
        id (int):
        major (str):
        minor (str):
        effect (str):
    """

    id: int
    major: str
    minor: str
    effect: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        major = self.major

        minor = self.minor

        effect = self.effect

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "major": major,
                "minor": minor,
                "effect": effect,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        id = d.pop("id")

        major = d.pop("major")

        minor = d.pop("minor")

        effect = d.pop("effect")

        group_permission_read = cls(
            id=id,
            major=major,
            minor=minor,
            effect=effect,
        )

        group_permission_read.additional_properties = d
        return group_permission_read

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
