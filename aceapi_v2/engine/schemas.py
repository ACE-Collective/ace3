"""Schemas for the engine API (ACE API v2)."""

from pydantic import BaseModel, ConfigDict, Field


class UploadModifiers(BaseModel):
    """How the receiving node treats an uploaded work target."""

    model_config = ConfigDict(extra="forbid", strict=True)

    overwrite: bool = Field(default=False, description="extract over a storage directory that already exists")
    sync: bool = Field(default=False, description="schedule the root for analysis on this node")
    move: bool = Field(default=False, description="the alert moves here: repoint its alerts row at this node")
    is_alert: bool = Field(default=True, description="the work target is an alert")


class UploadResult(BaseModel):
    result: bool = Field(description="always true; a failure is an error status")
    storage_dir: str = Field(description="where this node stored it, which the sender repoints rows at "
                                         "(it includes the node name, so the sender cannot compute it)")


class ClearResult(BaseModel):
    result: bool = Field(description="always true; a failure is an error status")
