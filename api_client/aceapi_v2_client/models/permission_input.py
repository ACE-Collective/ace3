from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="PermissionInput")


@_attrs_define
class PermissionInput:
    """
    Attributes:
        major (str):
        minor (str):
        effect (str | Unset):  Default: 'ALLOW'.
    """

    major: str
    minor: str
    effect: str | Unset = "ALLOW"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        major = self.major

        minor = self.minor

        effect = self.effect

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

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        major = d.pop("major")

        minor = d.pop("minor")

        effect = d.pop("effect", UNSET)

        permission_input = cls(
            major=major,
            minor=minor,
            effect=effect,
        )

        permission_input.additional_properties = d
        return permission_input

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
