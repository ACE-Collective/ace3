"""Observable schemas for ACE API v2."""

from datetime import date, datetime

from pydantic import BaseModel, Field

MAX_LOOKUP_PAIRS = 1000
MAX_RECENT_ALERTS = 20
DEFAULT_RECENT_ALERTS = 5
MAX_EXCLUDE_ALERT_UUIDS = 100


class SetInterestingRequest(BaseModel):
    observable_type: str
    observable_value: str
    is_interesting: bool


class LookupPair(BaseModel):
    """One type/value pair to look up. The value is the plain string form, exactly as an
    observable displays it (for a file observable, the content sha256 hex digest)."""
    type: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1)


class ObservableLookupRequest(BaseModel):
    """Batch prevalence lookup: how often, how recently, and with what dispositions each
    observable has appeared across alerts, and which events those alerts belong to.

    since bounds the counted/listed alerts by insert_date but does NOT filter events — an old
    event membership is still worth surfacing. exclude_alert_uuids removes specific alerts
    (typically the caller's own) from counts, recent alerts, and events; unknown UUIDs are
    silently ignored.
    """
    observables: list[LookupPair] = Field(min_length=1, max_length=MAX_LOOKUP_PAIRS)
    recent_alert_limit: int = Field(default=DEFAULT_RECENT_ALERTS, ge=0, le=MAX_RECENT_ALERTS)
    exclude_alert_uuids: list[str] = Field(default_factory=list, max_length=MAX_EXCLUDE_ALERT_UUIDS)
    since: datetime | None = None


class RecentAlertSummary(BaseModel):
    uuid: str
    disposition: str
    insert_date: datetime


class EventMembership(BaseModel):
    id: int
    uuid: str
    name: str
    creation_date: date
    status: str


class ObservableLookupResult(BaseModel):
    """Per-pair result, positionally aligned with the request (key on index, not value: the
    echoed type/value are the normalized forms, e.g. a lowercased file hash).

    Alerts with alert_type 'faqueue' are never counted. disposition_counts is the raw
    histogram including OPEN and UNKNOWN (unlike the GUI's disposition history, which drops
    UNKNOWN), so total_alert_count == sum(disposition_counts.values()) always holds.
    found=false with error=null means the observable has never been indexed; found=true with
    total_alert_count=0 means every containing alert was faqueue, excluded, or before since.
    """
    index: int
    type: str
    value: str | None = None
    found: bool = False
    error: str | None = None
    total_alert_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    disposition_counts: dict[str, int] = Field(default_factory=dict)
    recent_alerts: list[RecentAlertSummary] = Field(default_factory=list)
    events: list[EventMembership] = Field(default_factory=list)


class ObservableLookupResponse(BaseModel):
    results: list[ObservableLookupResult]
