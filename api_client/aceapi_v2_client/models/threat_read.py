from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

T = TypeVar("T", bound="ThreatRead")


@_attrs_define
class ThreatRead:
    """
    Attributes:
        malware_id (int):
        threat_type_id (int):
        threat_type_name (str):
    """

    malware_id: int
    threat_type_id: int
    threat_type_name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        malware_id = self.malware_id

        threat_type_id = self.threat_type_id

        threat_type_name = self.threat_type_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "malware_id": malware_id,
                "threat_type_id": threat_type_id,
                "threat_type_name": threat_type_name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        malware_id = d.pop("malware_id")

        threat_type_id = d.pop("threat_type_id")

        threat_type_name = d.pop("threat_type_name")

        threat_read = cls(
            malware_id=malware_id,
            threat_type_id=threat_type_id,
            threat_type_name=threat_type_name,
        )

        threat_read.additional_properties = d
        return threat_read

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
