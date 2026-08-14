from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from typing_extensions import Self

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.observable_comment_summary import ObservableCommentSummary


T = TypeVar("T", bound="ObservableDetectionRead")


@_attrs_define
class ObservableDetectionRead:
    """One curated detection, plus whatever the observables index knows about the same value.

    `observable_id`, `fa_hits` and `comments` come from a LEFT JOIN to `observables` and are empty
    for a detection added before the value was ever seen.

        Attributes:
            id (int):
            type_ (str):
            value (str):
            expires_on (datetime.datetime | None | Unset):
            detection_context (None | str | Unset):
            batch_id (None | str | Unset):
            created_by (None | str | Unset):
            created_at (datetime.datetime | None | Unset):
            modified_by (None | str | Unset):
            modified_at (datetime.datetime | None | Unset):
            observable_id (int | None | Unset):
            fa_hits (int | None | Unset):
            comments (list[ObservableCommentSummary] | Unset):
    """

    id: int
    type_: str
    value: str
    expires_on: datetime.datetime | None | Unset = UNSET
    detection_context: None | str | Unset = UNSET
    batch_id: None | str | Unset = UNSET
    created_by: None | str | Unset = UNSET
    created_at: datetime.datetime | None | Unset = UNSET
    modified_by: None | str | Unset = UNSET
    modified_at: datetime.datetime | None | Unset = UNSET
    observable_id: int | None | Unset = UNSET
    fa_hits: int | None | Unset = UNSET
    comments: list[ObservableCommentSummary] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

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

        created_by: None | str | Unset
        if isinstance(self.created_by, Unset):
            created_by = UNSET
        else:
            created_by = self.created_by

        created_at: None | str | Unset
        if isinstance(self.created_at, Unset):
            created_at = UNSET
        elif isinstance(self.created_at, datetime.datetime):
            created_at = self.created_at.isoformat()
        else:
            created_at = self.created_at

        modified_by: None | str | Unset
        if isinstance(self.modified_by, Unset):
            modified_by = UNSET
        else:
            modified_by = self.modified_by

        modified_at: None | str | Unset
        if isinstance(self.modified_at, Unset):
            modified_at = UNSET
        elif isinstance(self.modified_at, datetime.datetime):
            modified_at = self.modified_at.isoformat()
        else:
            modified_at = self.modified_at

        observable_id: int | None | Unset
        if isinstance(self.observable_id, Unset):
            observable_id = UNSET
        else:
            observable_id = self.observable_id

        fa_hits: int | None | Unset
        if isinstance(self.fa_hits, Unset):
            fa_hits = UNSET
        else:
            fa_hits = self.fa_hits

        comments: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.comments, Unset):
            comments = []
            for comments_item_data in self.comments:
                comments_item = comments_item_data.to_dict()
                comments.append(comments_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
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
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if modified_by is not UNSET:
            field_dict["modified_by"] = modified_by
        if modified_at is not UNSET:
            field_dict["modified_at"] = modified_at
        if observable_id is not UNSET:
            field_dict["observable_id"] = observable_id
        if fa_hits is not UNSET:
            field_dict["fa_hits"] = fa_hits
        if comments is not UNSET:
            field_dict["comments"] = comments

        return field_dict

    @classmethod
    def from_dict(cls, src_dict: Mapping[str, Any]) -> Self:
        from ..models.observable_comment_summary import ObservableCommentSummary

        d = dict(src_dict)
        id = d.pop("id")

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

        def _parse_created_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_by = _parse_created_by(d.pop("created_by", UNSET))

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

        def _parse_modified_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        modified_by = _parse_modified_by(d.pop("modified_by", UNSET))

        def _parse_modified_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                modified_at_type_0 = datetime.datetime.fromisoformat(data)

                return modified_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        modified_at = _parse_modified_at(d.pop("modified_at", UNSET))

        def _parse_observable_id(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        observable_id = _parse_observable_id(d.pop("observable_id", UNSET))

        def _parse_fa_hits(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        fa_hits = _parse_fa_hits(d.pop("fa_hits", UNSET))

        _comments = d.pop("comments", UNSET)
        comments: list[ObservableCommentSummary] | Unset = UNSET
        if _comments is not UNSET:
            comments = []
            for comments_item_data in _comments:
                comments_item = ObservableCommentSummary.from_dict(comments_item_data)

                comments.append(comments_item)

        observable_detection_read = cls(
            id=id,
            type_=type_,
            value=value,
            expires_on=expires_on,
            detection_context=detection_context,
            batch_id=batch_id,
            created_by=created_by,
            created_at=created_at,
            modified_by=modified_by,
            modified_at=modified_at,
            observable_id=observable_id,
            fa_hits=fa_hits,
            comments=comments,
        )

        observable_detection_read.additional_properties = d
        return observable_detection_read

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
