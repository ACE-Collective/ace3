"""SVS sample schemas for ACE API v2 (docs/SVS_API.md, *Samples*)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from aceapi_v2.detection_points.schemas import Verdict, VerdictSource

Label = Literal["tp", "fp", "conflicted"]
CaptureState = Literal["pending", "stored", "missing"]
MissingReason = Literal["file", "match_record", "storage"]


class SampleVotes(BaseModel):
    """How many contributing detections vote TP or FP, at each strength (verdict source)."""
    tp_explicit: int
    fp_explicit: int
    tp_inherited_single: int
    fp_inherited_single: int
    tp_inherited_multi: int
    fp_inherited_multi: int


class SampleRow(BaseModel):
    """One sample: a file and a YARA rule it matched, over every alert it was captured from.

    Timestamps are UTC."""

    sha256: str = Field(description="the file's sha256")
    rule_uuid: str = Field(description="the rule's uuid meta; the signature_uuid of its detections")
    rule_name: str = Field(description="the rule's name in the latest capture")
    namespace: str | None = Field(default=None, description="the rule's namespace in the latest capture, relative to the signature directory")
    file_path: str = Field(description="the file's path in the latest capture, relative to its alert's files directory")
    file_size: int | None = None
    capture_count: int = Field(description="how many captures (one per alert) the sample has")
    stored: int = Field(description="how many captures hold the file")
    missing: int = Field(description="how many captures could not keep the file (state missing)")
    missing_data: int = Field(description="how many captures lack something: the file, or the match record")
    unknown_version: int = Field(description="how many captures recorded signature version 'unknown'")
    first_captured: datetime
    last_captured: datetime
    updated_at: datetime = Field(description="the latest change of any of its captures")
    latest_capture_id: int
    label: Label | None = Field(
        default=None,
        description="the sample's grade for the rule, aggregated from the verdicts of its contributing "
                    "detections: tp, fp, or conflicted when votes of the strongest strength present "
                    "disagree; null when no detection has a verdict")
    label_source: VerdictSource | None = Field(
        default=None, description="the strength that decided the label: explicit > inherited_single > inherited_multi")
    votes: SampleVotes
    local: bool = Field(description="whether this node can serve the file: always with a shared pool")


class SampleListPage(BaseModel):
    data: list[SampleRow]
    next_cursor: str | None = Field(
        default=None,
        description="pass as ?cursor= with the same filters and sort for the next page; null on the last page")


# the CSV export's columns, in order; the votes are flattened into their own columns
SAMPLE_ROW_CSV_FIELDS = (
    *(name for name in SampleRow.model_fields if name != "votes"),
    *SampleVotes.model_fields,
)


class SampleDetection(BaseModel):
    """A contributing detection: a detection of the rule on the file, on the capture's alert."""
    content_hash: str
    verdict: Verdict | None = None
    verdict_source: VerdictSource | None = None
    override: Verdict | None = None
    override_user: str | None = None
    override_set_at: datetime | None = None


class SampleCapture(BaseModel):
    """One capture of the sample: the file as one alert had it."""
    id: int
    alert_uuid: str
    observable_uuid: str
    rule_name: str
    namespace: str | None = None
    signature_version: str = Field(description="the commit of the rule's repository when it matched, or 'unknown'")
    rule_content_hash: str | None = None
    file_path: str
    file_size: int | None = None
    yara_meta_tags: list[str]
    state: CaptureState
    missing_reason: MissingReason | None = None
    has_record: bool = Field(description="whether the match record is stored (GET /svs/samples/captures/{id}/record)")
    match_summary: dict[str, Any] = Field(
        description="the match record's summary: meta, tags, and per string how many times it matched and where first")
    yara_python_version: str | None = None
    yara_scanner_version: str | None = None
    node: str
    local: bool = Field(description="whether this node can serve the match record")
    created_at: datetime
    stored_at: datetime | None = None
    updated_at: datetime
    detections: list[SampleDetection] = Field(
        description="its contributing detections; empty when the alert was deleted")


class SampleDetail(SampleRow):
    captures: list[SampleCapture] = Field(description="every capture, newest first")


class MissingCount(BaseModel):
    rule_uuid: str
    rule_name: str
    reason: MissingReason
    count: int
