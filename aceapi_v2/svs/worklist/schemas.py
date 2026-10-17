"""Wire schemas for the declared-vs-measured worklist (/svs/worklist)."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class WorklistRow(BaseModel):
    """One signature's tag on, or measurement of, one ATT&CK technique, as of the last coverage
    refresh (the resolution as of now)."""

    signature_uuid: str
    technique: str = Field(description="the technique in the pinned ATT&CK release (a revoked tag id counts as its "
                                       "successor)")
    technique_name: Optional[str] = Field(default=None, description="its name in the pinned release")
    kind: str = Field(description="declared (a tag of the signature), undeclared (measured, but no tag names it) or "
                                  "unknown (a tag naming an id the release doesn't have)")
    status: str = Field(description="confirmed, open, kept, remove_pending, removed, undeclared, unknown or retired")
    declared_as: list[str] = Field(description="the tag ids, as the signature writes them, that count as the technique")
    tag_present: bool = Field(description="the signature has the tag now")
    signature_counts: bool = Field(description="the signature is enabled, and isn't a YARA rule in QA mode")
    counts: bool = Field(description="the tag counts toward coverage as a manual mapping (from the next refresh, "
                                     "after a resolution)")
    measured: bool = Field(description="the signature is expected of a catalog test")
    measured_techniques: list[str] = Field(description="the techniques the signature is measured on")
    signature_family: Optional[str] = None
    signature_name: Optional[str] = None
    resolution: Optional[str] = Field(default=None, description="keep or remove; null when nobody resolved the row")
    reason: Optional[str] = None
    reference: Optional[str] = Field(default=None, description="a link, such as the pull request removing the tag")
    resolved_by: Optional[str] = Field(default=None, description="the username of whoever resolved it")
    resolved_at: Optional[datetime] = None
    first_seen_at: datetime
    status_changed_at: datetime
    updated_at: datetime = Field(description="when the row last changed; the changed_since key")


class WorklistPage(BaseModel):
    data: list[WorklistRow]
    next_cursor: Optional[str] = None


WORKLIST_CSV_FIELDS = tuple(WorklistRow.model_fields)


class MeasuredTest(BaseModel):
    guid: str
    name: Optional[str] = None
    platform: str


class MeasuredTechnique(BaseModel):
    technique: str
    technique_name: Optional[str] = None
    tests: list[MeasuredTest] = Field(description="the catalog tests, on each platform, the signature is expected of")


class SignatureWorklist(BaseModel):
    """A signature's worklist rows, and what it is measured on now."""

    signature_uuid: str
    signature_family: Optional[str] = None
    signature_name: Optional[str] = None
    rows: list[WorklistRow] = Field(description="every row of the signature, retired ones included")
    measured: list[MeasuredTechnique] = Field(description="the techniques the signature is measured on now, with "
                                                          "the tests that measure it, computed at the request")


class ResolutionRequest(BaseModel):
    resolution: str = Field(description="keep (the tag covers something no test reaches) or remove (the signature "
                                        "repository will drop the tag)")
    reason: str = Field(max_length=4096, description="why; required")
    reference: Optional[str] = Field(default=None, max_length=1024,
                                     description="an http(s) link, such as the pull request removing the tag")


class WorklistKey(BaseModel):
    signature_uuid: str
    technique: str


class BulkResolutionRequest(ResolutionRequest):
    rows: list[WorklistKey] = Field(min_length=1, max_length=500)


class WorklistConflictItem(WorklistKey):
    status: str = Field(description="the row's status, which can't be resolved")


class BulkResolutionResult(BaseModel):
    done: list[WorklistKey] = Field(description="the rows resolved")
    conflicts: list[WorklistConflictItem] = Field(description="rows that are confirmed, informational, retired or "
                                                              "removed; left alone")
    unknown: list[WorklistKey] = Field(description="rows that don't exist")
