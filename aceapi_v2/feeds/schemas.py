"""Wire schemas for feeds (docs/FEED_WATCHES.md)."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

AuthType = Literal["none", "basic", "header"]


class FeedRequest(BaseModel):
    """A feed as feed:write adds it. auth_secret is the basic auth password or the header's value; it
    is stored encrypted and never returned."""
    name: str = Field(min_length=1, max_length=256)
    url: str = Field(min_length=1, max_length=2048, description="an http or https URL")
    poll_interval_seconds: Optional[int] = Field(default=None, description="at least feeds.min_poll_interval_seconds; unset for feeds.default_poll_interval_seconds")
    enabled: bool = True
    auth_type: AuthType = "none"
    auth_name: Optional[str] = Field(default=None, max_length=256, description="the basic auth user, or the header's name")
    auth_secret: Optional[str] = Field(default=None, max_length=4096)


class FeedUpdate(BaseModel):
    """The fields to change. auth_secret replaces the stored secret when given; auth_type none removes
    the credentials."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    url: Optional[str] = Field(default=None, min_length=1, max_length=2048)
    poll_interval_seconds: Optional[int] = None
    enabled: Optional[bool] = None
    auth_type: Optional[AuthType] = None
    auth_name: Optional[str] = Field(default=None, max_length=256)
    auth_secret: Optional[str] = Field(default=None, max_length=4096)


class Feed(BaseModel):
    id: int
    name: str
    url: str
    title: Optional[str] = Field(default=None, description="the feed's own title, from its last poll")
    poll_interval_seconds: int
    enabled: bool
    auth_type: AuthType
    auth_name: Optional[str] = None
    has_secret: bool = Field(description="credentials are stored; they are never shown")
    baselined_at: Optional[datetime] = Field(default=None, description="its first successful poll: entries seen then are for preview only")
    last_poll_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    last_error: Optional[str] = None
    next_poll_at: Optional[datetime] = None
    created_by: Optional[str] = None
    created_at: datetime


class FeedPage(BaseModel):
    data: list[Feed]
    next_cursor: Optional[str] = None


class FeedEntry(BaseModel):
    id: int
    feed_id: int
    identity: str
    title: Optional[str] = None
    link: Optional[str] = None
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    categories: list[str] = []
    text: str = Field(description="the entry's text (content, else summary), cut to text_max characters")
    text_truncated: bool
    content_hash: str
    baseline: bool = Field(description="seen in the feed's first poll: for preview only, never evaluated")
    first_seen_at: datetime
    last_seen_at: datetime


class FeedEntryPage(BaseModel):
    data: list[FeedEntry]
    next_cursor: Optional[str] = None
