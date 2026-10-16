"""Schemas for the remediation API (ACE API v2)."""

from pydantic import BaseModel, Field

from saq.remediation.types import RemediationAction


class RemediationTargetKey(BaseModel):
    """What a remediator acts on: the remediator, and the observable it remediates."""

    remediator: str = Field(description="the remediator's configured name")
    observable_type: str
    observable_value: str


class RemediationSummary(BaseModel):
    id: int
    action: str
    status: str = Field(description="NEW, IN_PROGRESS or COMPLETED")
    result: str | None = Field(default=None, description="how a completed remediation ended (SUCCESS, CANCELLED, ...)")


class RemediationTargetRead(RemediationTargetKey):
    remediator_display_name: str | None = Field(
        default=None, description="null when no remediator by that name is configured on this node")
    current: RemediationSummary | None = Field(
        default=None, description="the target's latest remediation, which cancel and delete act on")


class TargetLookupRequest(BaseModel):
    alert_uuids: list[str] = Field(min_length=1)


class QueueRemediationsRequest(BaseModel):
    """Queue one remediation per target. A restore uses the restore key of the target's latest
    successful removal."""

    action: RemediationAction
    targets: list[RemediationTargetKey] = Field(min_length=1)
