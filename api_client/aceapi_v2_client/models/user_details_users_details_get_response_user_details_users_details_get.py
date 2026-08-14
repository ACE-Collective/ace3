from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

if TYPE_CHECKING:
    from ..models.user_detail import UserDetail


T = TypeVar("T", bound="UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet")


@_attrs_define
class UserDetailsUsersDetailsGetResponseUserDetailsUsersDetailsGet:
    """ """

    additional_properties: dict[str, UserDetail] = _attrs_field(
        init=False, factory=dict
    )

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        for prop_name, prop in self.additional_properties.items():
            field_dict[prop_name] = prop.to_dict()

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        from ..models.user_detail import UserDetail

        d = dict(src_dict)
        user_details_users_details_get_response_user_details_users_details_get = cls()

        additional_properties = {}
        for prop_name, prop_dict in d.items():
            additional_property = UserDetail.from_dict(prop_dict)

            additional_properties[prop_name] = additional_property

        user_details_users_details_get_response_user_details_users_details_get.additional_properties = additional_properties
        return user_details_users_details_get_response_user_details_users_details_get

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> UserDetail:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: UserDetail) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
