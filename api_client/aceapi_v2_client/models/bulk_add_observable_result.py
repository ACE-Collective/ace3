from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.bulk_add_observable_result_failed_details import (
        BulkAddObservableResultFailedDetails,
    )


T = TypeVar("T", bound="BulkAddObservableResult")


@_attrs_define
class BulkAddObservableResult:
    """
    Attributes:
        success_count (int):
        failed_count (int):
        failed_uuids (list[str]):
        failed_details (BulkAddObservableResultFailedDetails | Unset):
    """

    success_count: int
    failed_count: int
    failed_uuids: list[str]
    failed_details: BulkAddObservableResultFailedDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        success_count = self.success_count

        failed_count = self.failed_count

        failed_uuids = self.failed_uuids

        failed_details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.failed_details, Unset):
            failed_details = self.failed_details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "success_count": success_count,
                "failed_count": failed_count,
                "failed_uuids": failed_uuids,
            }
        )
        if failed_details is not UNSET:
            field_dict["failed_details"] = failed_details

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        from ..models.bulk_add_observable_result_failed_details import (
            BulkAddObservableResultFailedDetails,
        )

        d = dict(src_dict)
        success_count = d.pop("success_count")

        failed_count = d.pop("failed_count")

        failed_uuids = cast(list[str], d.pop("failed_uuids"))

        _failed_details = d.pop("failed_details", UNSET)
        failed_details: BulkAddObservableResultFailedDetails | Unset
        if isinstance(_failed_details, Unset):
            failed_details = UNSET
        else:
            failed_details = BulkAddObservableResultFailedDetails.from_dict(
                _failed_details
            )

        bulk_add_observable_result = cls(
            success_count=success_count,
            failed_count=failed_count,
            failed_uuids=failed_uuids,
            failed_details=failed_details,
        )

        bulk_add_observable_result.additional_properties = d
        return bulk_add_observable_result

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
