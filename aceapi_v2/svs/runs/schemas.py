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
