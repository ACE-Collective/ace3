"""Archived email schemas for ACE API v2."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

# the same cap as the observable lookup, so one script batch fits both
MAX_MESSAGE_IDS = 1000

SHA256_PATTERN = "^[0-9a-f]{64}$"

# RFC 5322 limits a header line to 998 characters
MessageId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=998)]


class MessageIdsRequest(BaseModel):
    message_ids: list[MessageId] = Field(
        min_length=1, max_length=MAX_MESSAGE_IDS,
        description="Message-IDs, with or without the angle brackets")


class ArchivedEmailCopy(BaseModel):
    sha256: str = Field(description="the email's sha256: GET /email/archive/{sha256} returns it")
    archived_at: datetime = Field(description="the last time the email was archived under this Message-ID (UTC)")
    size: int = Field(description="the email's size in bytes")


class ArchiveLookupResult(BaseModel):
    """One requested Message-ID, at its position in the request.

    No copies and no expired_copies: ACE never archived an email with this Message-ID, or archived
    it too long ago for its row to be kept. No copies and some expired_copies: ACE archived it,
    and the email has since expired from the archive."""
    index: int
    message_id: str = Field(description="the Message-ID as the archive stores it, in angle brackets")
    copies: list[ArchivedEmailCopy] = Field(description="every archived email with this Message-ID, newest first")
    expired_copies: int = Field(description="emails archived under this Message-ID that have expired")


class ArchiveLookupResponse(BaseModel):
    results: list[ArchiveLookupResult]
