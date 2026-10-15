"""Wire schemas for the SVS ignores."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class IgnoreRequest(BaseModel):
    """An ignore, as svs:run_manage (a test's) or svs:admin (global) sets it."""

    reason: Optional[str] = Field(default=None, max_length=4096, description="why its detections during runs are noise")


class Ignore(BaseModel):
    scope: str = Field(description="global (every test's runs) or test")
    test_guid: Optional[str] = Field(default=None, description="the test, for a test's ignore")
    signature_uuid: str
    signature_family: Optional[str] = Field(default=None, description="the signature's family as last known")
    signature_name: Optional[str] = Field(default=None, description="the signature's name as last known")
    reason: Optional[str] = None
    created_by: Optional[str] = Field(default=None, description="who added it (username)")
    created_at: datetime
    updated_at: datetime = Field(description="the changed_since key")


class IgnorePage(BaseModel):
    data: list[Ignore]
    next_cursor: Optional[str] = None


IGNORE_CSV_FIELDS = tuple(Ignore.model_fields)
