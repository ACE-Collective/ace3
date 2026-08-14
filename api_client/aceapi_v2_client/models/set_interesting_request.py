from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

T = TypeVar("T", bound="SetInterestingRequest")


@_attrs_define
class SetInterestingRequest:
    """
    Attributes:
        observable_type (str):
        observable_value (str):
        is_interesting (bool):
    """

    observable_type: str
    observable_value: str
    is_interesting: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        observable_type = self.observable_type

        observable_value = self.observable_value

        is_interesting = self.is_interesting

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "observable_type": observable_type,
                "observable_value": observable_value,
                "is_interesting": is_interesting,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        observable_type = d.pop("observable_type")

        observable_value = d.pop("observable_value")

        is_interesting = d.pop("is_interesting")

        set_interesting_request = cls(
            observable_type=observable_type,
            observable_value=observable_value,
            is_interesting=is_interesting,
        )

        set_interesting_request.additional_properties = d
        return set_interesting_request

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
