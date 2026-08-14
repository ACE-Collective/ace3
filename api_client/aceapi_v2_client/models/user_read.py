from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

T = TypeVar("T", bound="UserRead")


@_attrs_define
class UserRead:
    """
    Attributes:
        id (int):
        username (str):
        enabled (bool):
        display_name (None | str | Unset):
        email (None | str | Unset):
        queue (None | str | Unset):
        timezone (None | str | Unset):
        api_key_count (int | Unset):  Default: 0.
    """

    id: int
    username: str
    enabled: bool
    display_name: None | str | Unset = UNSET
    email: None | str | Unset = UNSET
    queue: None | str | Unset = UNSET
    timezone: None | str | Unset = UNSET
    api_key_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        username = self.username

        enabled = self.enabled

        display_name: None | str | Unset
        if isinstance(self.display_name, Unset):
            display_name = UNSET
        else:
            display_name = self.display_name

        email: None | str | Unset
        if isinstance(self.email, Unset):
            email = UNSET
        else:
            email = self.email

        queue: None | str | Unset
        if isinstance(self.queue, Unset):
            queue = UNSET
        else:
            queue = self.queue

        timezone: None | str | Unset
        if isinstance(self.timezone, Unset):
            timezone = UNSET
        else:
            timezone = self.timezone

        api_key_count = self.api_key_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "username": username,
                "enabled": enabled,
            }
        )
        if display_name is not UNSET:
            field_dict["display_name"] = display_name
        if email is not UNSET:
            field_dict["email"] = email
        if queue is not UNSET:
            field_dict["queue"] = queue
        if timezone is not UNSET:
            field_dict["timezone"] = timezone
        if api_key_count is not UNSET:
            field_dict["api_key_count"] = api_key_count

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        d = dict(src_dict)
        id = d.pop("id")

        username = d.pop("username")

        enabled = d.pop("enabled")

        def _parse_display_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        display_name = _parse_display_name(d.pop("display_name", UNSET))

        def _parse_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        email = _parse_email(d.pop("email", UNSET))

        def _parse_queue(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        queue = _parse_queue(d.pop("queue", UNSET))

        def _parse_timezone(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        timezone = _parse_timezone(d.pop("timezone", UNSET))

        api_key_count = d.pop("api_key_count", UNSET)

        user_read = cls(
            id=id,
            username=username,
            enabled=enabled,
            display_name=display_name,
            email=email,
            queue=queue,
            timezone=timezone,
            api_key_count=api_key_count,
        )

        user_read.additional_properties = d
        return user_read

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
