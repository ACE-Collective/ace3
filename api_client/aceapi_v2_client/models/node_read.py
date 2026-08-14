from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.collector_status_read import CollectorStatusRead


T = TypeVar("T", bound="NodeRead")


@_attrs_define
class NodeRead:
    """
    Attributes:
        id (int):
        name (str):
        location (str):
        company_id (int):
        status (str):
        last_update (datetime.datetime):
        is_primary (bool):
        any_mode (bool):
        workload_count (int):
        delayed_analysis_count (int):
        collectors (list[CollectorStatusRead] | Unset):
    """

    id: int
    name: str
    location: str
    company_id: int
    status: str
    last_update: datetime.datetime
    is_primary: bool
    any_mode: bool
    workload_count: int
    delayed_analysis_count: int
    collectors: list[CollectorStatusRead] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        location = self.location

        company_id = self.company_id

        status = self.status

        last_update = self.last_update.isoformat()

        is_primary = self.is_primary

        any_mode = self.any_mode

        workload_count = self.workload_count

        delayed_analysis_count = self.delayed_analysis_count

        collectors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.collectors, Unset):
            collectors = []
            for collectors_item_data in self.collectors:
                collectors_item = collectors_item_data.to_dict()
                collectors.append(collectors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "location": location,
                "company_id": company_id,
                "status": status,
                "last_update": last_update,
                "is_primary": is_primary,
                "any_mode": any_mode,
                "workload_count": workload_count,
                "delayed_analysis_count": delayed_analysis_count,
            }
        )
        if collectors is not UNSET:
            field_dict["collectors"] = collectors

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        from ..models.collector_status_read import CollectorStatusRead

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        location = d.pop("location")

        company_id = d.pop("company_id")

        status = d.pop("status")

        last_update = datetime.datetime.fromisoformat(d.pop("last_update"))

        is_primary = d.pop("is_primary")

        any_mode = d.pop("any_mode")

        workload_count = d.pop("workload_count")

        delayed_analysis_count = d.pop("delayed_analysis_count")

        _collectors = d.pop("collectors", UNSET)
        collectors: list[CollectorStatusRead] | Unset = UNSET
        if _collectors is not UNSET:
            collectors = []
            for collectors_item_data in _collectors:
                collectors_item = CollectorStatusRead.from_dict(collectors_item_data)

                collectors.append(collectors_item)

        node_read = cls(
            id=id,
            name=name,
            location=location,
            company_id=company_id,
            status=status,
            last_update=last_update,
            is_primary=is_primary,
            any_mode=any_mode,
            workload_count=workload_count,
            delayed_analysis_count=delayed_analysis_count,
            collectors=collectors,
        )

        node_read.additional_properties = d
        return node_read

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
