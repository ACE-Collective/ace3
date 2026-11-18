"""Wire schemas for the SVS test hosts."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from saq.svs.hosts import MAX_IPS, MAX_USERNAMES, PLATFORMS


class TestHostRequest(BaseModel):
    """A test host as an svs:admin adds or replaces it. Names are matched case-insensitively."""

    __test__ = False

    hostname: str = Field(min_length=1, max_length=255, description="the short or fully qualified host name; a fully qualified one also sets fqdn")
    fqdn: Optional[str] = Field(default=None, max_length=255, description="the fully qualified name, when the host has one. A target named by a fully qualified name matches only this one")
    usernames: list[str] = Field(default_factory=list, max_length=MAX_USERNAMES, description="the users runs may use on the host, as user, DOMAIN\\user or user@domain; empty means any user")
    ips: list[str] = Field(default_factory=list, max_length=MAX_IPS, description="the host's addresses")
    platform: Optional[str] = Field(default=None, description=f"one of {', '.join(PLATFORMS)}, when known: a test that doesn't support it can't target the host")
    notes: Optional[str] = Field(default=None, max_length=4096)


class TestHost(BaseModel):
    __test__ = False

    id: int
    hostname: str = Field(description="the short name, lower case")
    fqdn: Optional[str] = None
    usernames: list[str] = Field(description="bare user names, lower case; empty means any user")
    ips: list[str]
    platform: Optional[str] = None
    notes: Optional[str] = None
    created_by: Optional[str] = Field(default=None, description="who added it (username)")
    created_at: datetime
    updated_at: datetime


class TestHostPage(BaseModel):
    __test__ = False

    data: list[TestHost]
    next_cursor: Optional[str] = None


TEST_HOST_CSV_FIELDS = ("id", "hostname", "fqdn", "usernames", "ips", "platform", "notes", "created_by", "created_at",
                        "updated_at")


class MaintenanceRequest(BaseModel):
    minutes: int = Field(ge=1, description="how long the window stays open, up to svs.runs.max_maintenance_minutes")
    reason: str = Field(min_length=1, max_length=2048, description="why: kept with the window and in the comment of every alert closed for it")


class MaintenanceWindow(BaseModel):
    """A test host's maintenance window (docs/SVS_RUNS.md, *Maintenance windows*)."""

    id: str = Field(description="the window's uuid; svs_maintenance in ACE's logs")
    host: str = Field(description="the test host, by its short name")
    fqdn: Optional[str] = None
    reason: str
    opened_by: str = Field(description="who opened it: the key's or user's name")
    opened_at: datetime
    ends_at: datetime = Field(description="when it was opened to end")
    ended_at: Optional[datetime] = Field(default=None, description="when it ended: early, or at ends_at")
    ended_by: Optional[str] = Field(default=None, description="who ended it; svs when it expired")
    end_reason: Optional[str] = Field(default=None, description="ended or expired")
    open: bool = Field(description="it hasn't ended")


class MaintenancePage(BaseModel):
    data: list[MaintenanceWindow]
    next_cursor: Optional[str] = None
