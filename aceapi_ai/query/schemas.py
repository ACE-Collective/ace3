from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AIQueryRequestBody(BaseModel):
    query: str
    start_time: datetime
    end_time: datetime
    limit: int | None = Field(default=None, ge=1)
    timeout_seconds: int | None = Field(default=None, ge=1)
    extras: dict[str, Any] = Field(default_factory=dict)

    @field_validator("start_time", "end_time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        # naive datetimes silently shift the window by the reader's assumption; refuse them
        if value.tzinfo is None:
            raise ValueError("must be timezone-aware (use an explicit UTC offset, e.g. 2026-01-01T00:00:00Z)")
        return value


class AIQueryResponse(BaseModel):
    backend: str
    rows: list[dict]
    row_count: int
    truncated: bool
    truncation_reason: str | None
    window_start: datetime
    window_end: datetime
    duration_ms: int
    meta: dict[str, Any]


class BackendDescriptor(BaseModel):
    name: str
    authorized: bool
    describe: dict[str, Any]
