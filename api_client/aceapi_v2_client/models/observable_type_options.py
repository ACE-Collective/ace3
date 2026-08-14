from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

T = TypeVar("T", bound="ObservableTypeOptions")


@_attrs_define
class ObservableTypeOptions:
    """Type lists for the page: `present` filters the table, `all` populates the create form.

    Attributes:
        present (list[str]):
        all_ (list[str]):
    """

    present: list[str]
    all_: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        present = self.present

        all_ = self.all_

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "present": present,
                "all": all_,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        present = cast(list[str], d.pop("present"))

        all_ = cast(list[str], d.pop("all"))

        observable_type_options = cls(
            present=present,
            all_=all_,
        )

        observable_type_options.additional_properties = d
        return observable_type_options

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
