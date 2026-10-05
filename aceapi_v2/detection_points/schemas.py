"""Detection point schemas for ACE API v2."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal["tp", "fp"]
VerdictSource = Literal["explicit", "inherited_single", "inherited_multi"]


class DetectionPointRow(BaseModel):
    """One detection of an alert, with its effective verdict (docs/SVS.md, Part 1).

    Timestamps are UTC."""

    alert_uuid: str
    content_hash: str = Field(
        description="the detection's stable identity within its alert: a hash of the node it sits "
                    "on, its signature, description and details. Verdicts are keyed on it")
    description: str
    details: Any | None = Field(default=None, description="the detection's structured details, if any")
    queue: str | None = Field(default=None, description="the queue the detection asked its alert to be routed to")
    signature_uuid: str
    signature_version: str
    signature_family: str | None = Field(
        default=None, description="yara, hunt, observable_modifier or builtin; null if unknown")
    node_kind: str | None = Field(
        default=None, description="root, observable or analysis; null on a row synced before node identity")
    node_type: str | None = Field(
        default=None, description="the observable's type (for an analysis node, the analyzed observable's)")
    node_value_sha256: str | None = Field(
        default=None, description="the observable's observables.sha256 key in hex; a file's content sha256")
    node_module_path: str | None = Field(default=None, description="the analysis module, for an analysis node")
    insert_date: datetime
    verdict: Verdict | None = Field(
        default=None, description="the effective verdict; null when the alert's disposition is unclassified")
    verdict_source: VerdictSource | None = Field(
        default=None,
        description="explicit: set or confirmed by an analyst. inherited_single: inherited from the "
                    "alert, which covered this detection directly (an FP alert, or a TP alert with one "
                    "signature). inherited_multi: inherited TP on an alert where several signatures "
                    "fired, unconfirmed")
    override: Verdict | None = Field(
        default=None, description="the stored explicit verdict, if any; masked on an FP alert")
    override_user: str | None = None
    override_set_at: datetime | None = None


class VerdictRequest(BaseModel):
    verdict: Verdict


class ConfirmResult(BaseModel):
    confirmed: int = Field(description="how many unconfirmed (inherited_multi) detections were confirmed")


class DetectionPointListPage(BaseModel):
    data: list[DetectionPointRow]
    next_cursor: str | None = Field(
        default=None,
        description="pass as ?cursor= with the same filters for the next page; null on the last page")


# the CSV export's columns, in order; details are written as JSON
DETECTION_POINT_ROW_CSV_FIELDS = tuple(DetectionPointRow.model_fields)
