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
