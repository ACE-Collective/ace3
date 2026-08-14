from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectionCreate")


@_attrs_define
class DetectionCreate:
    """Add a detection. The observable need not have ever been seen.

    Attributes:
        type_ (str):
        value (str):
        expires_on (datetime.datetime | None | Unset):
        detection_context (None | str | Unset):
        batch_id (None | str | Unset):
    """

    type_: str
    value: str
    expires_on: datetime.datetime | None | Unset = UNSET
    detection_context: None | str | Unset = UNSET
    batch_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_

        value = self.value

        expires_on: None | str | Unset
        if isinstance(self.expires_on, Unset):
            expires_on = UNSET
        elif isinstance(self.expires_on, datetime.datetime):
            expires_on = self.expires_on.isoformat()
        else:
            expires_on = self.expires_on

        detection_context: None | str | Unset
        if isinstance(self.detection_context, Unset):
            detection_context = UNSET
        else:
            detection_context = self.detection_context

        batch_id: None | str | Unset
        if isinstance(self.batch_id, Unset):
            batch_id = UNSET
        else:
            batch_id = self.batch_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "value": value,
            }
        )
        if expires_on is not UNSET:
            field_dict["expires_on"] = expires_on
        if detection_context is not UNSET:
            field_dict["detection_context"] = detection_context
        if batch_id is not UNSET:
            field_dict["batch_id"] = batch_id

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        type_ = d.pop("type")

        value = d.pop("value")

        def _parse_expires_on(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                expires_on_type_0 = datetime.datetime.fromisoformat(data)

                return expires_on_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        expires_on = _parse_expires_on(d.pop("expires_on", UNSET))

        def _parse_detection_context(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detection_context = _parse_detection_context(d.pop("detection_context", UNSET))

        def _parse_batch_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        batch_id = _parse_batch_id(d.pop("batch_id", UNSET))

        detection_create = cls(
            type_=type_,
            value=value,
            expires_on=expires_on,
            detection_context=detection_context,
            batch_id=batch_id,
        )

        detection_create.additional_properties = d
        return detection_create

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
