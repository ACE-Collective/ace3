from typing import Optional

from pydantic import BaseModel, Field

from enum import Enum

# NOTE this corresponds directly to the status column in the remediation table
# TODO just use this Enum in the database model!
class RemediationStatus(Enum):
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"

# remediator statuses
class RemediatorStatus(Enum):
    DELAYED = 'DELAYED'
    ERROR = 'ERROR'
    FAILED = 'FAILED'
    IGNORE = 'IGNORE'
    SUCCESS = 'SUCCESS'
    CANCELLED = 'CANCELLED'

    @property
    def completed(self) -> bool:
        """Returns True if the status indicates that the remediation is complete."""
        return self in [self.FAILED, self.IGNORE, self.SUCCESS, self.CANCELLED]

    @property
    def in_progress(self) -> bool:
        """Returns True if the status indicates that the remediation is in progress."""
        return self in [self.DELAYED]

    @property
    def failure(self) -> bool:
        """Returns True if the status indicates that the remediation failed."""
        return self in [self.ERROR, self.FAILED]

    @property
    def remediation_status(self) -> RemediationStatus:
        """Returns the RemediationStatus corresponding to this RemediatorStatus."""
        if self.in_progress:
            return RemediationStatus.IN_PROGRESS
        else:
            return RemediationStatus.COMPLETED

# remediation actions
class RemediationAction(Enum):
    REMOVE = 'remove'
    RESTORE = 'restore'

class RemediatorResult(BaseModel):
    status: RemediatorStatus = Field(..., description="The status of the remediation result.")
    message: Optional[str] = Field(default=None, description="The message of the remediation result.")
    restore_key: Optional[str] = Field(default=None, description="The restore key of the remediation result.")

class RemediationWorkItem(BaseModel):
    id: int = Field(..., description="The database id of the remediation.")
    action: RemediationAction = Field(..., description="The action of the remediation.")
    name: str = Field(..., description="The name of the remediator that initiated the remediation.") # remediator "name" (office365_email, etc...)
    type: str = Field(..., description="The type of the remediation.") # observable type
    key: str = Field(..., description="The key of the remediation.") # observable value
    restore_key: Optional[str] = Field(default=None, description="The restore key of the remediation.")
