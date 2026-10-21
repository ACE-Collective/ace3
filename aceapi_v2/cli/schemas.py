"""CLI execution schemas for ACE API v2."""

from datetime import datetime

from pydantic import BaseModel, Field

# a run longer than this belongs in cron or a service, not behind a browser tab
MAX_TIMEOUT_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 300


class CliExecutionCreate(BaseModel):
    command: str = Field(
        min_length=1, max_length=8192,
        description="the command line after `ace`, e.g. `cas verify --pool yara_qa`; a leading `ace` is ignored")
    node_ids: list[int] | None = Field(
        default=None, min_length=1,
        description="the nodes to run it on, once on each; the primary node when omitted")
    timeout_seconds: int = Field(
        default=DEFAULT_TIMEOUT_SECONDS, ge=1, le=MAX_TIMEOUT_SECONDS,
        description="the run is stopped (SIGTERM, then SIGKILL) after this many seconds")


class CliExecutionSummary(BaseModel):
    id: int
    # None once the user is deleted; username is kept on the row
    user_id: int | None
    username: str
    node_id: int
    node_name: str
    command: str
    status: str
    exit_code: int | None
    error: str | None
    timeout_seconds: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class CliExecutionRead(CliExecutionSummary):
    output: str | None
    output_truncated: bool


class CliExecutionListPage(BaseModel):
    data: list[CliExecutionSummary]
    next_cursor: str | None = Field(
        default=None,
        description="pass as ?cursor= for the next (older) page; null on the last page")


class CliExecutionStarted(BaseModel):
    id: int
    status: str


class CliNodeRead(BaseModel):
    id: int
    name: str
    status: str
    is_primary: bool
    last_update: datetime
