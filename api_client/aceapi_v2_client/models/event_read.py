from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

T = TypeVar("T", bound="EventRead")


@_attrs_define
class EventRead:
    """An event serialized from ``Event.json``.

    ``Event.json`` produces a wide, semi-dynamic dict (nested malware/threats,
    list-valued tags/companies/alerts, an ``owner`` sub-object, etc.). Rather
    than re-enumerate every field — and risk drifting from the source of truth —
    this model declares the stable scalar fields and allows the remainder
    through unchanged.

        Attributes:
            id (int):
            uuid (str):
            name (str):
    """

    id: int
    uuid: str
    name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        uuid = self.uuid

        name = self.name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "uuid": uuid,
                "name": name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        id = d.pop("id")

        uuid = d.pop("uuid")

        name = d.pop("name")

        event_read = cls(
            id=id,
            uuid=uuid,
            name=name,
        )

        event_read.additional_properties = d
        return event_read

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
