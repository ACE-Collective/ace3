"""Plain data types shared by every consumer of the search subsystem (Flask, FastAPI, CLI).

These are dataclasses rather than pydantic models so the GUI and the CLI can use them without
pulling in the API layer; aceapi_v2/search/schemas.py mirrors them for the wire format.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

LANE_SEMANTIC = "semantic"
LANE_LEXICAL = "lexical"
ALL_LANES = frozenset({LANE_SEMANTIC, LANE_LEXICAL})

# document kinds stored in the index
KIND_ALERT = "alert"
KIND_COMMENT = "comment"
KIND_DETECTION = "detection"
KIND_ANALYSIS = "analysis"
KIND_CONTEXT = "context"

# hit kinds produced by the lexical lane
KIND_OBSERVABLE = "observable"
KIND_TAG = "tag"
KIND_UUID = "uuid"

# relative relevance tiers (never raw scores -- see docs/SEARCH.md)
TIER_EXACT = "exact"
TIER_STRONG = "strong"
TIER_GOOD = "good"
TIER_WEAK = "weak"


@dataclass(frozen=True)
class SearchFilters:
    """Pre-filters applied to both lanes before ranking.

    Every list is a disjunction (any of the values); the `*_inverted` flags negate the whole
    condition. `locations` is the node scoping the caller is allowed to see (None = unscoped).
    """

    insert_date_ranges: tuple[tuple[datetime, datetime], ...] = ()
    insert_date_inverted: bool = False
    alert_types: tuple[str, ...] = ()
    alert_types_inverted: bool = False
    dispositions: tuple[str, ...] = ()
    dispositions_inverted: bool = False
    queues: tuple[str, ...] = ()
    queues_inverted: bool = False
    tags: tuple[str, ...] = ()
    tags_inverted: bool = False
    locations: Optional[tuple[str, ...]] = None
    exclude_alert_uuids: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not any([
            self.insert_date_ranges,
            self.alert_types,
            self.dispositions,
            self.queues,
            self.tags,
            self.locations is not None,
            self.exclude_alert_uuids,
        ])


@dataclass(frozen=True)
class SearchRequest:
    query: str
    filters: SearchFilters = field(default_factory=SearchFilters)
    limit: int = 50
    offset: int = 0
    include_hits: bool = True
    lanes: frozenset[str] = ALL_LANES


@dataclass(frozen=True)
class SearchHit:
    """One piece of evidence for why an alert matched."""

    lane: str
    kind: str
    key: str
    title: Optional[str]
    text: str
    score: float
    analysis_uuid: Optional[str] = None
    observable_uuid: Optional[str] = None


@dataclass
class AlertSearchResult:
    alert_uuid: str
    rank: int
    fused_score: float
    tier: str
    hits: list[SearchHit] = field(default_factory=list)
    lanes: frozenset[str] = frozenset()
    # the evidence behind the tier: best dense cosine and best sparse (term) score of the alert
    dense_score: Optional[float] = None
    sparse_score: Optional[float] = None


@dataclass
class SearchResponse:
    query: str
    total: int
    offset: int
    limit: int
    results: list[AlertSearchResult] = field(default_factory=list)
    lanes_used: frozenset[str] = frozenset()
    timings_ms: dict[str, int] = field(default_factory=dict)

    @property
    def alert_uuids(self) -> list[str]:
        return [result.alert_uuid for result in self.results]

    def has_more(self) -> bool:
        return self.offset + len(self.results) < self.total
