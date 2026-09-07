"""Wire schemas for alert search (mirrors saq/search/types.py)."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

MAX_QUERY_LENGTH = 2000
MAX_PAGE_SIZE = 100
MAX_SIMILAR_PAGE_SIZE = 50
MAX_EXCLUDE_ALERT_UUIDS = 100
MAX_FILTER_VALUES = 100

Lane = Literal["semantic", "lexical"]


class SearchFiltersBody(BaseModel):
    """Pre-filters applied before ranking. Lists match any of their values."""

    insert_date_start: Optional[datetime] = Field(default=None, description="only alerts created at or after this time (timezone-aware)")
    insert_date_end: Optional[datetime] = Field(default=None, description="only alerts created at or before this time (timezone-aware)")
    alert_types: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES)
    dispositions: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES, description="e.g. OPEN, FALSE_POSITIVE, DELIVERY")
    queues: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES)
    tags: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES, description="exact tag names (case-insensitive)")
    exclude_alert_uuids: list[str] = Field(default_factory=list, max_length=MAX_EXCLUDE_ALERT_UUIDS)

    @field_validator("insert_date_start", "insert_date_end")
    @classmethod
    def require_timezone(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            raise ValueError("must be timezone-aware (use an explicit UTC offset, e.g. 2026-01-01T00:00:00Z)")
        return value


class AlertSearchRequest(BaseModel):
    """Hybrid search over alerts: exact indicator/tag/uuid matches plus semantic matches over
    the alert's text (description, comments, detections, email content, command lines, ...)."""

    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH, description="free text, an indicator, a tag, or an alert uuid")
    filters: SearchFiltersBody = Field(default_factory=SearchFiltersBody)
    limit: int = Field(default=20, ge=1, le=MAX_PAGE_SIZE, description="page size")
    offset: int = Field(default=0, ge=0)
    include_hits: bool = Field(default=True, description="include the matching snippets for each alert")
    lanes: list[Lane] = Field(default_factory=lambda: ["semantic", "lexical"], min_length=1)


class SimilarAlertsRequest(BaseModel):
    """Alerts most similar to a given alert, by the alert's own indexed text."""

    alert_uuid: str
    filters: SearchFiltersBody = Field(default_factory=SearchFiltersBody)
    limit: int = Field(default=10, ge=1, le=MAX_SIMILAR_PAGE_SIZE)
    offset: int = Field(default=0, ge=0)
    include_hits: bool = True


class SearchHitOut(BaseModel):
    lane: Lane
    kind: str = Field(description="alert, comment, detection, analysis, context (semantic) or observable, tag, uuid (lexical)")
    title: Optional[str] = None
    text: str
    score: float = Field(description="lane-native score: 1.0 for an exact match, the fused qdrant score for a semantic hit; not comparable across lanes")


class AlertSummaryOut(BaseModel):
    uuid: str
    description: str
    alert_type: Optional[str] = None
    tool: Optional[str] = None
    tool_instance: Optional[str] = None
    queue: Optional[str] = None
    disposition: Optional[str] = None
    disposition_time: Optional[datetime] = None
    insert_date: Optional[datetime] = None
    owner: Optional[str] = None
    location: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class AlertSearchResultOut(BaseModel):
    alert: AlertSummaryOut
    rank: int
    tier: Literal["exact", "strong", "good", "weak"] = Field(description="the evidence behind the match: exact = an indicator/tag/uuid matched verbatim; strong = clearly similar text (or similar text sharing terms with the query); good = similar text above the floor; weak = only a term in common")
    score: float = Field(description="fused rank score (for ordering only)")
    lanes: list[Lane]
    hits: list[SearchHitOut] = Field(default_factory=list)


class AlertSearchResponse(BaseModel):
    query: str
    total: int = Field(description="number of matching alerts (capped by the search.max_results setting)")
    offset: int
    limit: int
    results: list[AlertSearchResultOut]
    lanes_used: list[Lane]
    timings_ms: dict[str, int]
