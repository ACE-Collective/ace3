from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="SecretEntry")


@_attrs_define
class SecretEntry:
    """One named secret and its status. Never includes the value.

    Attributes:
        key (str):
        is_set (bool):
        is_referenced (bool):
        is_overridden (bool | Unset):  Default: False.
    """

    key: str
    is_set: bool
    is_referenced: bool
    is_overridden: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        key = self.key

        is_set = self.is_set

        is_referenced = self.is_referenced

        is_overridden = self.is_overridden

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "key": key,
                "is_set": is_set,
                "is_referenced": is_referenced,
            }
        )
        if is_overridden is not UNSET:
            field_dict["is_overridden"] = is_overridden

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        key = d.pop("key")

        is_set = d.pop("is_set")

        is_referenced = d.pop("is_referenced")

        is_overridden = d.pop("is_overridden", UNSET)

        secret_entry = cls(
            key=key,
            is_set=is_set,
            is_referenced=is_referenced,
            is_overridden=is_overridden,
        )

        secret_entry.additional_properties = d
        return secret_entry

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
