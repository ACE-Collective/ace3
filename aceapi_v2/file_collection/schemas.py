"""Schemas for the file collection API (ACE API v2)."""

from datetime import datetime

from pydantic import BaseModel, Field


class FileCollectionRow(BaseModel):
    """One file collection request in the listing (file_collection:read). Timestamps are UTC."""

    id: int
    collector: str = Field(description="the file collector's configured name")
    observable_type: str
    observable_value: str
    status: str = Field(description="NEW, IN_PROGRESS (waiting to be tried again) or COMPLETED")
    result: str | None = Field(default=None, description="how the latest attempt ended (SUCCESS, HOST_OFFLINE, ...)")
    result_message: str | None = None
    retry_count: int = Field(description="the attempts so far")
    max_retries: int
    alert_uuid: str | None = Field(default=None, description="the alert that asked for the file")
    requested_by: str | None = Field(default=None, description="the display name of the analyst who asked for it")
    collected_file_sha256: str | None = None
    insert_date: datetime
    update_time: datetime | None = None


class FileCollectionListPage(BaseModel):
    data: list[FileCollectionRow]
    next_cursor: str | None = Field(
        default=None, description="pass as ?cursor= with the same filters for the next page; null on the last page")


# the CSV export's columns, in order
FILE_COLLECTION_ROW_CSV_FIELDS = tuple(FileCollectionRow.model_fields)


class FileCollectionSummary(BaseModel):
    id: int
    status: str
    result: str | None = None
    retry_count: int


class FileCollectionHistoryEntry(BaseModel):
    """One attempt of a file collector at a request. Timestamps are UTC."""

    insert_date: datetime
    result: str
    status: str
    message: str
