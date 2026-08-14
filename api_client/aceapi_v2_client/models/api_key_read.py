from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.api_key_scope import ApiKeyScope


T = TypeVar("T", bound="ApiKeyRead")


@_attrs_define
class ApiKeyRead:
    """API key metadata for the management UI. Never carries the secret.

    Attributes:
        id (int):
        name (str):
        inherit_user_scope (bool):
        scope (list[ApiKeyScope] | Unset):
        created_at (datetime.datetime | None | Unset):
        created_by (int | None | Unset):
    """

    id: int
    name: str
    inherit_user_scope: bool
    scope: list[ApiKeyScope] | Unset = UNSET
    created_at: datetime.datetime | None | Unset = UNSET
    created_by: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        inherit_user_scope = self.inherit_user_scope

        scope: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.scope, Unset):
            scope = []
            for scope_item_data in self.scope:
                scope_item = scope_item_data.to_dict()
                scope.append(scope_item)

        created_at: None | str | Unset
        if isinstance(self.created_at, Unset):
            created_at = UNSET
        elif isinstance(self.created_at, datetime.datetime):
            created_at = self.created_at.isoformat()
        else:
            created_at = self.created_at

        created_by: int | None | Unset
        if isinstance(self.created_by, Unset):
            created_by = UNSET
        else:
            created_by = self.created_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "inherit_user_scope": inherit_user_scope,
            }
        )
        if scope is not UNSET:
            field_dict["scope"] = scope
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if created_by is not UNSET:
            field_dict["created_by"] = created_by

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        from ..models.api_key_scope import ApiKeyScope

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        inherit_user_scope = d.pop("inherit_user_scope")

        _scope = d.pop("scope", UNSET)
        scope: list[ApiKeyScope] | Unset = UNSET
        if _scope is not UNSET:
            scope = []
            for scope_item_data in _scope:
                scope_item = ApiKeyScope.from_dict(scope_item_data)

                scope.append(scope_item)

        def _parse_created_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                created_at_type_0 = datetime.datetime.fromisoformat(data)

                return created_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        created_at = _parse_created_at(d.pop("created_at", UNSET))

        def _parse_created_by(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        created_by = _parse_created_by(d.pop("created_by", UNSET))

        api_key_read = cls(
            id=id,
            name=name,
            inherit_user_scope=inherit_user_scope,
            scope=scope,
            created_at=created_at,
            created_by=created_by,
        )

        api_key_read.additional_properties = d
        return api_key_read

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
