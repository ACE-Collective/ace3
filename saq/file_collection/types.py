from typing import Optional

from pydantic import BaseModel, Field

from enum import Enum


# NOTE this corresponds directly to the status column in the file_collection table
class FileCollectionStatus(Enum):
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class FileCollectorStatus(Enum):
    """Status values returned by FileCollector implementations."""
    DELAYED = 'DELAYED'
    ERROR = 'ERROR'
    FAILED = 'FAILED'
    SUCCESS = 'SUCCESS'
    CANCELLED = 'CANCELLED'
    HOST_OFFLINE = 'HOST_OFFLINE'
    FILE_NOT_FOUND = 'FILE_NOT_FOUND'

    @property
    def is_final(self) -> bool:
        """Returns True if this status is final and no more retries should be attempted."""
        return self in [self.SUCCESS, self.FILE_NOT_FOUND, self.FAILED, self.CANCELLED]

    @property
    def is_retryable(self) -> bool:
        """Returns True if this status indicates the collection should be retried."""
        return self in [self.DELAYED, self.HOST_OFFLINE, self.ERROR]

    @property
    def collection_status(self) -> FileCollectionStatus:
        """Returns the FileCollectionStatus corresponding to this FileCollectorStatus."""
        if self.is_final:
            return FileCollectionStatus.COMPLETED
        return FileCollectionStatus.IN_PROGRESS


class FileCollectorResult(BaseModel):
    """Result returned by a FileCollector.collect() call."""
    status: FileCollectorStatus = Field(..., description="The status of the collection attempt.")
    message: Optional[str] = Field(default=None, description="A message describing the result.")
    collected_file_path: Optional[str] = Field(default=None, description="Path to the collected file on success.")
    collected_file_sha256: Optional[str] = Field(default=None, description="SHA256 hash of the collected file.")


class FileCollectionWorkItem(BaseModel):
    """A work item representing a file collection request."""
    id: int = Field(..., description="The database id of the file collection request.")
    name: str = Field(..., description="The name of the FileCollector that will handle this collection.")
    type: str = Field(..., description="The observable type (e.g., file_location).")
    key: str = Field(..., description="The observable value (e.g., hostname@/path/to/file).")
    alert_uuid: Optional[str] = Field(default=None, description="UUID of the originating alert.")
    storage_dir: Optional[str] = Field(default=None, description="Path to the alert's storage directory for collected files.")
    retry_count: int = Field(default=0, description="Number of previous retry attempts.")
    max_retries: int = Field(default=10, description="Maximum number of retry attempts.")
