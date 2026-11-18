"""Wire schemas for a test's expectations and settings."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class ExpectationRequest(BaseModel):
    """A decision about a signature for a test on a platform, as svs:run_manage makes it."""

    state: Literal["expected", "rejected"] = Field(
        description="expected: a run of the test should fire it; rejected: it fires, but it is not what the test is "
                    "about, and it is not proposed again")
    reason: Optional[str] = Field(default=None, max_length=4096)
    run_id: Optional[str] = Field(
        default=None, description="the run (of this test, on this platform) whose result the decision was made from; "
                                  "its event log records it")


class Expectation(BaseModel):
    test_guid: str
    platform: str = Field(description="the platform the decision is about: only the test's runs on it are judged by it")
    signature_uuid: str
    state: str = Field(description="expected or rejected")
    signature_family: Optional[str] = Field(default=None, description="the signature's family as last known")
    signature_name: Optional[str] = Field(default=None, description="the signature's name as last known")
    reason: Optional[str] = None
    decided_from_run_id: Optional[str] = Field(default=None, description="the uuid of the run the decision was made from")
    decided_by: Optional[str] = Field(default=None, description="who decided (username)")
    decided_at: datetime
    updated_at: datetime = Field(description="the changed_since key")


class ExpectationPage(BaseModel):
    data: list[Expectation]
    next_cursor: Optional[str] = None


class TestSettingsRequest(BaseModel):
    """A test's settings, as svs:run_manage sets them."""

    __test__ = False

    observation_minutes: Optional[int] = Field(
        default=None,
        description="the observation window of the test's runs registered from now on, used as it is (no slack, no "
                    "floor), from 1 minute up to svs.runs.observation_window.ceiling_hours; null for the computed "
                    "window")
    holds_host: bool = Field(
        default=False,
        description="the test leaves something behind on its hosts, so each run of it registered from now on holds "
                    "them until its attribution window ends, not its observation window (docs/SVS_RUNS.md, *One run "
                    "per test host*)")


class TestSettings(BaseModel):
    __test__ = False

    test_guid: str
    observation_minutes: Optional[int] = Field(default=None, description="null: the computed window")
    holds_host: bool = False
    set_by: Optional[str] = Field(default=None, description="who set them (username)")
    updated_at: datetime


EXPECTATION_CSV_FIELDS = tuple(Expectation.model_fields)
