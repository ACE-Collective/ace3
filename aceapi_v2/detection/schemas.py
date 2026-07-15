"""Schemas for the observable-detection settings API (ACE API v2)."""

from datetime import datetime

from pydantic import BaseModel


class ObservableCommentSummary(BaseModel):
    """A single analyst comment on an observable, for read-only display on the detection page."""
    comment: str
    user_display_name: str
    insert_date: datetime


class ObservableDetectionRead(BaseModel):
    id: int
    type: str
    value: str
    for_detection: bool
    expires_on: datetime | None = None
    detection_modified_by: str | None = None
    detection_context: str | None = None
    batch_id: str | None = None
    comments: list[ObservableCommentSummary] = []


class ObservablePage(BaseModel):
    """One page of observables plus the counters the UI needs to render page controls."""
    items: list[ObservableDetectionRead]
    total: int
    page: int
    page_size: int
    total_pages: int

    @property
    def first_index(self) -> int:
        """1-based index of the first row on this page (0 when empty)."""
        return 0 if not self.items else (self.page - 1) * self.page_size + 1

    @property
    def last_index(self) -> int:
        return (self.page - 1) * self.page_size + len(self.items)

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


class DetectionUpdate(BaseModel):
    enabled: bool
    detection_context: str | None = None


class ExpirationUpdate(BaseModel):
    expires_on: datetime | None = None
