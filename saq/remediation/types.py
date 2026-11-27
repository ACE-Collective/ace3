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
    # the target does not exist where the remediator looked for it (e.g. the email is not in the
    # mailbox because something else already removed it, or it was never delivered). Nothing was
    # done, but there is nothing left for the analyst to act on either, so this is complete
    # without being a failure.
    NOT_FOUND = 'NOT_FOUND'

    @property
    def completed(self) -> bool:
        """Returns True if the status indicates that the remediation is complete."""
        return self in [self.FAILED, self.IGNORE, self.SUCCESS, self.CANCELLED, self.NOT_FOUND]

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

# The values of the alert manage page's Remediation filter are [source, state] pairs. The state is
# one of the states the Remediation column shows (saq/remediation/coverage.py), with the label the
# filter editor gives it. Saved filters and share links store the values, so a state is never
# renamed; a label can change.
ALERT_REMEDIATION_FILTER_OPTIONS = {
    "remediated": "Remediated",
    "partial": "Partially Remediated",
    "failed": "Remediation Failed",
    "remediating": "Remediating",
    "watching": "Watching",
    "not_remediated": "Not Remediated",
    "not_in_mailbox": "Not In Mailbox",
    "none": "None",
}

# The source of a Remediation filter value that counts every remediator and probe, as the column
# does. Any other source is the name of one remediator (remediation.name) or one probe
# (external_remediation_check.probe_name), and the state is then read from its rows alone.
REMEDIATION_SOURCE_ANY = "Any"

def normalize_alert_remediation_value(value) -> list[str]:
    """A [source, state] value of the Remediation filter as it is stored: Any in any case becomes
    Any, and the state is lowercased. Raises ValueError for anything that is not one."""
    if not (isinstance(value, (list, tuple)) and len(value) == 2 and all(isinstance(v, str) for v in value)):
        raise ValueError(f"remediation values must be [source, state] pairs, got {value!r}")

    source, state = value[0].strip(), value[1].lower()
    if not source:
        raise ValueError(f"remediation value {value!r} names no source (use {REMEDIATION_SOURCE_ANY} for every source)")
    if state not in ALERT_REMEDIATION_FILTER_OPTIONS:
        raise ValueError(
            f"remediation states must be one of {', '.join(ALERT_REMEDIATION_FILTER_OPTIONS)}, got {value[1]!r}")

    if source.casefold() == REMEDIATION_SOURCE_ANY.casefold():
        source = REMEDIATION_SOURCE_ANY
    return [source, state]

class RemediatorResult(BaseModel):
    status: RemediatorStatus = Field(..., description="The status of the remediation result.")
    message: Optional[str] = Field(default=None, description="The message of the remediation result.")
    restore_key: Optional[str] = Field(default=None, description="The restore key of the remediation result.")
    resolved_target: Optional[str] = Field(default=None, description="What the remediator acted on when it was not the key itself, such as the mailbox that owns an alias address.")

class RemediationWorkItem(BaseModel):
    id: int = Field(..., description="The database id of the remediation.")
    action: RemediationAction = Field(..., description="The action of the remediation.")
    name: str = Field(..., description="The name of the remediator that initiated the remediation.") # remediator "name" (office365_email, etc...)
    type: str = Field(..., description="The type of the remediation.") # observable type
    key: str = Field(..., description="The key of the remediation.") # observable value
    restore_key: Optional[str] = Field(default=None, description="The restore key of the remediation.")
    lock: Optional[str] = Field(default=None, description="The lock uuid the collector placed on the database record when it handed out this work item.")
