from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkAddObservableRequest")


@_attrs_define
class BulkAddObservableRequest:
    """
    Attributes:
        alert_uuids (list[str]):
        observable_type (str):
        observable_value (str):
        observable_time (None | str | Unset):
        directives (list[str] | Unset):
    """

    alert_uuids: list[str]
    observable_type: str
    observable_value: str
    observable_time: None | str | Unset = UNSET
    directives: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        alert_uuids = self.alert_uuids

        observable_type = self.observable_type

        observable_value = self.observable_value

        observable_time: None | str | Unset
        if isinstance(self.observable_time, Unset):
            observable_time = UNSET
        else:
            observable_time = self.observable_time

        directives: list[str] | Unset = UNSET
        if not isinstance(self.directives, Unset):
            directives = self.directives

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "alert_uuids": alert_uuids,
                "observable_type": observable_type,
                "observable_value": observable_value,
            }
        )
        if observable_time is not UNSET:
            field_dict["observable_time"] = observable_time
        if directives is not UNSET:
            field_dict["directives"] = directives

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        alert_uuids = cast(list[str], d.pop("alert_uuids"))

        observable_type = d.pop("observable_type")

        observable_value = d.pop("observable_value")

        def _parse_observable_time(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        observable_time = _parse_observable_time(d.pop("observable_time", UNSET))

        directives = cast(list[str], d.pop("directives", UNSET))

        bulk_add_observable_request = cls(
            alert_uuids=alert_uuids,
            observable_type=observable_type,
            observable_value=observable_value,
            observable_time=observable_time,
            directives=directives,
        )

        bulk_add_observable_request.additional_properties = d
        return bulk_add_observable_request

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
