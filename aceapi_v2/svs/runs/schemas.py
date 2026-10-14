"""Wire schemas for SVS test runs."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from saq.svs.constants import RunState


class RunTargetRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255, description="a test host, by its short or fully qualified name")
    username: Optional[str] = Field(default=None, max_length=255, description="the user the test runs as (user, DOMAIN\\user or user@domain); required when the test host lists its users")


class RunRegistrationRequest(BaseModel):
    test_guid: str = Field(min_length=1, max_length=36, description="the auto_generated_guid of a test in the Atomic Red Team catalog (/api/v2/svs/tests)")
    targets: list[RunTargetRequest] = Field(min_length=1, description="the test hosts the test runs on")
    launcher: str = Field(min_length=1, max_length=256, description="the name of the launcher registering the run")
    batch_id: Optional[str] = Field(default=None, min_length=1, max_length=256, description="a label shared by runs registered together")
    extra: dict[str, Any] = Field(default_factory=dict, description="anything else the launcher wants kept with the run; stored and shown on the run page, at most svs.runs.max_extra_bytes as JSON")


class RunExecutedRequest(BaseModel):
    exit_code: int = Field(description="the test's exit code; anything but 0 moves the run to error")
    error: Optional[str] = Field(default=None, max_length=8192, description="what went wrong, when the launcher knows; moves the run to error")


class RunTarget(BaseModel):
    hostname: str = Field(description="as registered")
    username: Optional[str] = Field(default=None, description="as registered")
    host: str = Field(description="the short host name, lower case")
    fqdn: Optional[str] = None
    user: Optional[str] = Field(default=None, description="the bare user name, lower case")


class RunLifecycle(BaseModel):
    """A run as the launcher's calls return it."""

    run_id: str = Field(description="the run's uuid")
    marker: str = Field(description="put this where the test's process telemetry shows it (docs/SVS_RUNS.md, *The marker*)")
    state: RunState
    test_guid: str
    targets: list[RunTarget]
    observation_seconds: int = Field(description="how long after start the run waits for its alerts before it ends")
    attribution_seconds: int = Field(description="how long after start its alerts are still attributed to it")
    created_at: datetime
    started_at: Optional[datetime] = None
    observation_ends_at: Optional[datetime] = None
    attribution_ends_at: Optional[datetime] = None
    error_reason: Optional[str] = None
    close_reason: Optional[str] = None


#
# reading runs (svs:run_read)
#

class RunRow(BaseModel):
    """A run as the runs screen lists it."""

    run_id: str = Field(description="the run's uuid")
    state: RunState
    test_guid: str = Field(description="the catalog test (/api/v2/svs/tests/{guid})")
    test_name: Optional[str] = Field(default=None, description="from the catalog")
    technique: Optional[str] = Field(default=None, description="the test's ATT&CK technique, from the catalog")
    technique_name: Optional[str] = None
    marker: str = Field(description="the run's marker; svs_marker in ACE's logs")
    targets: list[RunTarget]
    launcher: str
    batch_id: Optional[str] = None
    created_at: datetime = Field(description="when the run was registered")
    started_at: Optional[datetime] = None
    executed_at: Optional[datetime] = Field(default=None, description="when the launcher reported how the test executed")
    exit_code: Optional[int] = None
    ended_at: Optional[datetime] = None
    canceled_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    observation_ends_at: Optional[datetime] = Field(default=None, description="when a started run ends")
    attribution_ends_at: Optional[datetime] = Field(default=None, description="until when alerts are attributed to it")
    error_reason: Optional[str] = None
    close_reason: Optional[str] = None
    owner: Optional[str] = Field(default=None, description="the owner's username")
    reviewer: Optional[str] = Field(default=None, description="who reviewed it, by username")
    reviewed_at: Optional[datetime] = None
    changed_since_review: bool = Field(description="a late alert or a manual association came after the review")
    needs_attention: bool = Field(description="the run is in the Needs attention view (docs/SVS_API.md, *Runs*)")
    updated_at: datetime = Field(description="when the row last changed; the changed_since key")


class RunDetail(RunRow):
    extra: Optional[dict[str, Any]] = Field(default=None, description="what the launcher sent with the registration")
    launcher_error: Optional[str] = Field(default=None, description="the error the launcher reported through executed")
    test_content_hash: str = Field(description="the test's content_hash when the run was registered")
    catalog_commit: str = Field(description="the catalog repository's commit when the run was registered")
    observation_seconds: int
    attribution_seconds: int
    registered_by: Optional[str] = Field(default=None, description="the username of the key that registered it")


class RunPage(BaseModel):
    data: list[RunRow]
    next_cursor: Optional[str] = None


class RunEvent(BaseModel):
    """One row of a run's event log."""

    id: int = Field(description="the event's id; a run's events are in id order")
    run_id: str = Field(description="the run's uuid")
    kind: str = Field(description="what happened: registered, transition, launcher_call, ... (docs/SVS_API.md, *Run events*)")
    from_state: Optional[RunState] = None
    to_state: Optional[RunState] = None
    actor: str = Field(description="who did it: the caller's name, or svs for a timer")
    actor_user: Optional[str] = Field(default=None, description="the actor's username, when the actor is a user")
    details: Optional[dict[str, Any]] = Field(default=None, description="what the event carries; its shape depends on kind")
    created_at: datetime
    updated_at: datetime = Field(description="the feed's changed_since key")


class RunEventPage(BaseModel):
    data: list[RunEvent]
    next_cursor: Optional[str] = None


RUN_ROW_CSV_FIELDS = tuple(RunRow.model_fields)
RUN_EVENT_CSV_FIELDS = tuple(RunEvent.model_fields)
