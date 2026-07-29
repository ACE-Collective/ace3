"""Schemas for the observable-detection settings API (ACE API v2)."""

from datetime import datetime

from pydantic import BaseModel


class ObservableCommentSummary(BaseModel):
    """A single analyst comment on an observable, for read-only display on the detection page."""
    comment: str
    user_display_name: str
    insert_date: datetime


class ObservableDetectionRead(BaseModel):
    """One curated detection, plus whatever the observables index knows about the same value.

    `observable_id`, `fa_hits` and `comments` come from a LEFT JOIN to `observables` and are empty
    for a detection added before the value was ever seen.
    """
    id: int
    type: str
    value: str
    expires_on: datetime | None = None
    detection_context: str | None = None
    batch_id: str | None = None
    created_by: str | None = None
    created_at: datetime | None = None
    modified_by: str | None = None
    modified_at: datetime | None = None
    observable_id: int | None = None
    fa_hits: int | None = None
    comments: list[ObservableCommentSummary] = []


class DetectionPage(BaseModel):
    """One page of detections plus the counters the UI needs to render page controls."""
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


class DetectionCreate(BaseModel):
    """Add a detection. The observable need not have ever been seen."""
    type: str
    value: str
    expires_on: datetime | None = None
    detection_context: str | None = None
    batch_id: str | None = None


class ObservableTypeOptions(BaseModel):
    """Type lists for the page: `present` filters the table, `all` populates the create form."""
    present: list[str]
    all: list[str]


class ExpirationUpdate(BaseModel):
    expires_on: datetime | None = None
