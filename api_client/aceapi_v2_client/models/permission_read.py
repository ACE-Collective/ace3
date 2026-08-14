from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="PermissionRead")


@_attrs_define
class PermissionRead:
    """
    Attributes:
        id (int):
        major (str):
        minor (str):
        effect (str):
        source (str):
        group_id (int | None | Unset):
    """

    id: int
    major: str
    minor: str
    effect: str
    source: str
    group_id: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        major = self.major

        minor = self.minor

        effect = self.effect

        source = self.source

        group_id: int | None | Unset
        if isinstance(self.group_id, Unset):
            group_id = UNSET
        else:
            group_id = self.group_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "major": major,
                "minor": minor,
                "effect": effect,
                "source": source,
            }
        )
        if group_id is not UNSET:
            field_dict["group_id"] = group_id

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        id = d.pop("id")

        major = d.pop("major")

        minor = d.pop("minor")

        effect = d.pop("effect")

        source = d.pop("source")

        def _parse_group_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        group_id = _parse_group_id(d.pop("group_id", UNSET))

        permission_read = cls(
            id=id,
            major=major,
            minor=minor,
            effect=effect,
            source=source,
            group_id=group_id,
        )

        permission_read.additional_properties = d
        return permission_read

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
