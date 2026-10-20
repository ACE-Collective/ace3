"""Alert schemas for ACE API v2."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints


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
    """One alert as a flat database row: the base of what GET /api/v2/alerts lists
    (AlertListRow) and of the AI API's export rows.

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
    svs_status: str | None = Field(
        default=None,
        description="the alert's SVS status: test, test? (attributed by context only), partial or mismatch; "
                    "null for an alert no test run touched (docs/SVS_RUNS.md, *Attribution*)")
    svs_runs: list[str] = Field(
        default_factory=list,
        description="the uuids of the SVS test runs the alert is attributed to (GET /api/v2/svs/runs/{run_id})")


class AlertListRow(AlertRow):
    """One alert as GET /api/v2/alerts lists and exports it: the row plus the analysts' comments."""

    comments: list[str] = Field(default_factory=list, description="the comments on the alert, oldest first")


class AlertListPage(BaseModel):
    data: list[AlertListRow]
    next_cursor: str | None = Field(
        default=None,
        description="pass as ?cursor= with the same filters for the next page; null on the last page")


# the CSV export's columns, in order; tags and svs_runs are joined with ",", comments with a newline
ALERT_ROW_CSV_FIELDS = tuple(AlertListRow.model_fields)


class AlertCount(BaseModel):
    count: int


class SetOwnerRequest(BaseModel):
    alert_uuids: list[str] = Field(min_length=1)
    owner_id: int | None = Field(
        description="the user who gets the alerts: the caller's own id takes them, null unassigns them")
    take_owned: dict[str, int] = Field(
        default_factory=dict,
        description="alert uuid -> id of the analyst the caller agreed to take it from. An alert another "
                    "analyst owns is changed only when it is named here with that analyst; otherwise it is "
                    "left alone and reported in `skipped`.")


class SetOwnerResult(BaseModel):
    applied: list[str] = Field(description="the alerts that now have the requested owner, in the order asked for")
    skipped: dict[str, str] = Field(description="alert uuid -> display name of the analyst left owning it")
    message: str | None = Field(
        default=None, description="what the GUI tells the analyst when alerts were skipped; null otherwise")


class DateRange(BaseModel):
    """A date filter value resolved to the window it means right now."""
    start: datetime
    end: datetime
    text: str = Field(description="the window as the manage page shows it, in the requested timezone")


class AlertMeta(BaseModel):
    """The parts of an alert that change while an analyst has it open, for the alert page's poll.

    Everything here is database state, so it is read without loading the alert from disk.
    """
    disposition: str | None = None
    disposition_user_id: int | None = None
    disposition_user_name: str | None = None
    owner_id: int | None = None
    owner_name: str | None = None
    owner_time: str | None = Field(default=None, description="ISO 8601, UTC, with a Z suffix")
    is_locked: bool
    status: str
    version: str


class AlertCommentUpdate(BaseModel):
    comment: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class AlertCommentRead(BaseModel):
    comment_id: int
    alert_uuid: str
    insert_date: datetime
    user_id: int
    user_display_name: str
    comment: str


class ObservableAnalysisRequested(BaseModel):
    """An analyst asked for analysis of one observable; the alert is queued for it."""
    message: str


class ClickerSearch(BaseModel):
    name: str = Field(description="the clicker search's configured name")
    url: str = Field(description="the search in the Splunk web interface")
