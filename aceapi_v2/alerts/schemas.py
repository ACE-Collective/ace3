"""Alert schemas for ACE API v2."""

from datetime import datetime

from pydantic import BaseModel, Field


class BulkAddObservableRequest(BaseModel):
    alert_uuids: list[str]
    observable_type: str
    observable_value: str
    observable_time: str | None = None
    directives: list[str] = []


class BulkAddObservableResult(BaseModel):
    success_count: int
    failed_count: int
    failed_uuids: list[str]
    failed_details: dict[str, str] = {}


class AlertRow(BaseModel):
    """One alert as a flat database row: what GET /api/v2/alerts lists and exports.

    Timestamps are UTC. Users are usernames, the company is its name."""

    uuid: str
    insert_date: datetime
    event_time: datetime | None = None
    disposition_time: datetime | None = None
    owner_time: datetime | None = None
    updated_at: datetime = Field(description="when the row last changed; the changed_since key")
    tool: str | None = None
    tool_instance: str | None = None
    alert_type: str | None = None
    description: str | None = None
    priority: int | None = None
    queue: str
    disposition: str | None = None
    disposition_user: str | None = None
    owner: str | None = None
    company: str | None = None
    location: str
    archived: bool
    tags: list[str] = Field(default_factory=list)
    detection_count: int = 0


class AlertListPage(BaseModel):
    data: list[AlertRow]
    next_cursor: str | None = Field(
        default=None,
        description="pass as ?cursor= with the same filters for the next page; null on the last page")


# the CSV export's columns, in order; tags are joined with ","
ALERT_ROW_CSV_FIELDS = tuple(AlertRow.model_fields)
