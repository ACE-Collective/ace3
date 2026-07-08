"""Schemas for the observable-detection settings API (ACE API v2)."""

from datetime import datetime

from pydantic import BaseModel


class ObservableDetectionRead(BaseModel):
    id: int
    type: str
    value: str
    for_detection: bool
    expires_on: datetime | None = None
    enabled_by: str | None = None
    detection_context: str | None = None
    batch_id: str | None = None


class DetectionUpdate(BaseModel):
    enabled: bool
    detection_context: str | None = None


class ExpirationUpdate(BaseModel):
    expires_on: datetime | None = None
