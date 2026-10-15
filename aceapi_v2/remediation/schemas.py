"""Schemas for the remediation API (ACE API v2)."""

from datetime import datetime

from pydantic import BaseModel, Field, model_validator

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


class ObservableKey(BaseModel):
    type: str = Field(description="an observable type")
    value: str


class TargetLookupRequest(BaseModel):
    """The alerts, or the observables, to find the remediation targets of: exactly one of the two."""

    alert_uuids: list[str] = Field(default_factory=list, description="the targets of every observable in these alerts")
    observables: list[ObservableKey] = Field(default_factory=list, description="the targets of these observables")

    @model_validator(mode="after")
    def _one_of(self) -> "TargetLookupRequest":
        if bool(self.alert_uuids) == bool(self.observables):
            raise ValueError("give either alert_uuids or observables")
        return self


class QueueRemediationsRequest(BaseModel):
    """Queue one remediation per target. A restore uses the restore key of the target's latest
    successful removal."""

    action: RemediationAction
    targets: list[RemediationTargetKey] = Field(min_length=1)


class RemediationRow(BaseModel):
    """One remediation in the listing (remediation:read). Timestamps are UTC."""

    id: int
    remediator: str = Field(description="the remediator's configured name")
    observable_type: str
    observable_value: str
    action: str = Field(description="remove or restore")
    status: str = Field(description="NEW, IN_PROGRESS or COMPLETED")
    result: str | None = Field(default=None, description="how the latest attempt ended (SUCCESS, DELAYED, ...)")
    analyst: str | None = Field(default=None, description="the display name of the analyst who asked for it")
    insert_date: datetime
    update_time: datetime | None = None


class RemediationListPage(BaseModel):
    data: list[RemediationRow]
    next_cursor: str | None = Field(
        default=None, description="pass as ?cursor= with the same filters for the next page; null on the last page")


# the CSV export's columns, in order
REMEDIATION_ROW_CSV_FIELDS = tuple(RemediationRow.model_fields)


class RemediationHistoryEntry(BaseModel):
    """One attempt of the remediation service at a remediation. Timestamps are UTC."""

    insert_date: datetime
    result: str
    status: str
    message: str
