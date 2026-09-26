"""Wire schemas for alert search (mirrors saq/search/types.py)."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from aceapi_v2.observables.schemas import LookupPair
from aceapi_v2.saved_filters.schemas import FilterEntry
from saq.gui.detection_point_value import normalize_detection_point_value

MAX_QUERY_LENGTH = 2000
MAX_PAGE_SIZE = 100
MAX_SIMILAR_PAGE_SIZE = 50
MAX_EXCLUDE_ALERT_UUIDS = 100
MAX_FILTER_VALUES = 100

Lane = Literal["semantic", "lexical"]


class SearchFiltersBody(BaseModel):
    """Filters applied before ranking. Lists match any of their values; the filters themselves
    are ANDed together."""

    insert_date_start: Optional[datetime] = Field(default=None, description="only alerts created at or after this time (timezone-aware)")
    insert_date_end: Optional[datetime] = Field(default=None, description="only alerts created at or before this time (timezone-aware)")
    alert_types: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES)
    dispositions: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES, description="e.g. OPEN, FALSE_POSITIVE, DELIVERY")
    queues: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES)
    tags: list[str] = Field(default_factory=list, max_length=MAX_FILTER_VALUES, description="exact tag names (case-insensitive)")
    exclude_alert_uuids: list[str] = Field(default_factory=list, max_length=MAX_EXCLUDE_ALERT_UUIDS)
    observables: list[LookupPair] = Field(
        default_factory=list, max_length=MAX_FILTER_VALUES,
        description="only alerts carrying ALL of these observables; the value is normalized the "
                    "same way the analysis engine normalizes it, and a file observable's value is "
                    "its content sha256 hex digest")
    detection_points: list[str] = Field(
        default_factory=list, max_length=MAX_FILTER_VALUES,
        description="only alerts with a detection point from ANY of these signatures, each written "
                    "<signature uuid>[:<signature version>]; without a version any version matches")
    filters: list[FilterEntry] = Field(
        default_factory=list, max_length=MAX_FILTER_VALUES,
        description="the rest of the alert management filter vocabulary, in the same "
                    "{name, inverted, values} shape the GUI and share links use -- e.g. "
                    "{\"name\": \"Owner\", \"inverted\": true, \"values\": [\"None\"]}")

    @field_validator("insert_date_start", "insert_date_end")
    @classmethod
    def require_timezone(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            raise ValueError("must be timezone-aware (use an explicit UTC offset, e.g. 2026-01-01T00:00:00Z)")
        return value

    @field_validator("detection_points")
    @classmethod
    def validate_detection_points(cls, values: list[str]) -> list[str]:
        return [normalize_detection_point_value(value) for value in values]

    def is_empty(self) -> bool:
        return not any([
            self.insert_date_start, self.insert_date_end, self.alert_types, self.dispositions,
            self.queues, self.tags, self.exclude_alert_uuids, self.observables, self.detection_points,
            self.filters,
        ])


class AlertSearchRequest(BaseModel):
    """Hybrid search over alerts: exact matches for the things named with a `field:value` term,
    plus semantic matches over the alert's text (description, comments, detections, email
    content, command lines, ...).

    Either `query` or `filters` is required. With filters and no query the response is a plain
    newest-first listing: no ranking, and every result's `tier` is null.
    """

    query: Optional[str] = Field(
        default=None, max_length=MAX_QUERY_LENGTH,
        description="free text for the semantic lanes, plus any number of `field:value` terms. "
                    "A term is `tag:phish`, `uuid:<alert uuid>`, `<observable type>:<value>` "
                    "(e.g. `ipv4:1.2.3.4`, `signature_id:<uuid>`), `observable:<type>:<value>` "
                    "for values containing colons, or a filter slug such as `queue:default`, "
                    "`disposition:DELIVERY`, `alert_date:-7d` or `detection_point:<signature uuid>[:<version>]`. Prefix with `-` to invert, "
                    "quote a value containing a space or comma, separate ORed values with "
                    "commas. An unrecognized prefix is ordinary text. A bare word or indicator "
                    "is searched semantically only -- it never runs an exact lookup.")
    filters: SearchFiltersBody = Field(default_factory=SearchFiltersBody)
    limit: int = Field(default=20, ge=1, le=MAX_PAGE_SIZE, description="page size")
    offset: int = Field(default=0, ge=0)
    include_hits: bool = Field(default=True, description="include the matching snippets for each alert")
    lanes: list[Lane] = Field(default_factory=lambda: ["semantic", "lexical"], min_length=1)

    @model_validator(mode="after")
    def require_query_or_filters(self) -> "AlertSearchRequest":
        if not (self.query or "").strip() and self.filters.is_empty():
            raise ValueError("a query or at least one filter is required")
        return self


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
    tier: Optional[Literal["exact", "strong", "good", "weak"]] = Field(default=None, description="the evidence behind the match: exact = a field term matched verbatim; strong = clearly similar text (or similar text sharing terms with the query); good = similar text above the floor; weak = only a term in common. null on a filter-only request, which is a listing rather than a ranking")
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
    errors: list[str] = Field(default_factory=list, description="query language problems. When this is non-empty nothing was searched: a term that cannot be honored is reported rather than dropped, because dropping it would return MORE alerts than were asked for")
