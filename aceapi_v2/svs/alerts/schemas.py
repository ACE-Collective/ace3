"""Wire schemas for one alert's side of SVS (/alerts/{uuid}/svs)."""

from typing import Optional

from pydantic import BaseModel, Field


class AlertSVSRun(BaseModel):
    run_id: str = Field(description="the run's uuid")
    state: str
    test_guid: str
    test_name: Optional[str] = Field(default=None, description="null when the catalog no longer has the test")


class AlertSVSDetection(BaseModel):
    content_hash: str = Field(description="the detection's content hash, as GET /alerts/{uuid}/detection-points has it")
    run_ids: list[str] = Field(description="the runs it is attributed to")


class AlertSVSMismatch(BaseModel):
    marker: str
    result: str = Field(description="how it disagrees with its run: unknown, other host or outside window")
    run: Optional[AlertSVSRun] = Field(default=None, description="the run the marker belongs to; null when no run has it")


class AlertSVS(BaseModel):
    """What SVS makes of one alert (docs/SVS.md, Part 3, *What analysts see*)."""

    alert_uuid: str
    svs_status: Optional[str] = Field(default=None, description="test, test?, partial or mismatch; null for none")
    runs: list[AlertSVSRun] = Field(default_factory=list, description="the runs whose attributions hold, oldest first")
    detections: list[AlertSVSDetection] = Field(default_factory=list, description="the attributed detections")
    mismatches: list[AlertSVSMismatch] = Field(default_factory=list,
                                               description="the markers in the alert that disagree with their run")


class AlertDisassociationRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=4096, description="why, as each run's event log records it")


class AlertDisassociation(BaseModel):
    """What disassociating the alert from its runs left it with."""

    alert_uuid: str
    run_ids: list[str] = Field(description="the runs it was disassociated from")
    svs_status: Optional[str] = Field(default=None, description="test, test?, partial or mismatch; null for none")
    queue: str
    moved: bool = Field(description="the alert moved back to the queue SVS took it from")
    reopened: bool = Field(description="the alert was SIMULATED and is OPEN again")
