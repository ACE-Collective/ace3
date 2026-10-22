"""Wire schemas for the Atomic Red Team test catalog (/svs/tests)."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class CatalogTest(BaseModel):
    """An Atomic Red Team test, by its auto_generated_guid."""

    guid: str = Field(description="the test's auto_generated_guid, lower case")
    repository: str = Field(description="the name of the git_repo_* section it is read from")
    technique: str = Field(description="the ATT&CK technique of its atomic file, e.g. T1059.001")
    technique_name: Optional[str] = None
    name: str
    platforms: list[str] = Field(description="its supported_platforms")
    executor: Optional[str] = Field(default=None, description="command_prompt, powershell, sh, bash or manual")
    path: str = Field(description="its atomic file, relative to the repository")
    commit: str = Field(description="the repository commit this version of the test was first read from")
    content_hash: str = Field(description="sha256 of the test's entry; it changes exactly when the test does")
    first_seen_at: datetime
    removed_at: Optional[datetime] = Field(default=None, description="when the test disappeared from its repository; it keeps its runs")
    updated_at: datetime = Field(description="when the catalog row last changed; the changed_since key. A change "
                                             "to the test's runs or state doesn't change it")
    test_state: str = Field(description="never_run, awaiting_review, no_expectations, failing, stale or validated: "
                                        "never_run without runs, else the worst of its platforms' states "
                                        "(docs/SVS_API.md, *Tests*)")
    run_count: int = Field(default=0, description="every run registered for it")
    last_run_id: Optional[str] = Field(default=None, description="its latest run's uuid")
    last_run_at: Optional[datetime] = Field(default=None, description="when its latest run was registered")
    last_reviewed_run_id: Optional[str] = None
    last_reviewed_at: Optional[datetime] = None
    expected_signatures: int = Field(default=0, description="signatures expected of it on any platform that no ignore "
                                                            "applies to")
    recent_runs: int = Field(default=0, description="its latest ended or reviewed runs looked at (at most 5)")
    recent_runs_missing: int = Field(default=0, description="of those, the runs that missed an expected signature")


class PlatformState(BaseModel):
    """How a test does on one platform."""

    platform: str
    test_state: str = Field(description="never_run (no run or decision on it), awaiting_review, no_expectations, "
                                        "failing, stale or validated")
    last_reviewed_run_id: Optional[str] = Field(default=None, description="its latest reviewed run on the platform")
    last_reviewed_at: Optional[datetime] = None
    expected_signatures: int = Field(default=0, description="signatures expected of it on the platform that no ignore "
                                                            "applies to")


class CatalogTestDetail(CatalogTest):
    platform_states: list[PlatformState] = Field(
        default_factory=list, description="each platform it supports or has a run or a decision on, by platform")
    description: Optional[str] = None
    test: dict[str, Any] = Field(description="the test's entry in its atomic file: executor (commands), input_arguments, dependencies")


class CatalogTestPage(BaseModel):
    data: list[CatalogTest]
    next_cursor: Optional[str] = None


CATALOG_TEST_CSV_FIELDS = tuple(CatalogTest.model_fields)


class CatalogRepository(BaseModel):
    """A catalog repository and the commit the catalog reflects (docs/SVS_RUNS.md, *The Atomic Red
    Team catalog*)."""

    name: str = Field(description="the name of its git_repo_* section")
    configured: bool = Field(description="it is in svs.catalog.repositories; one that isn't is listed while it has a row")
    git_url: Optional[str] = Field(default=None, description="from its git_repo_* section, without credentials; null without one")
    branch: Optional[str] = Field(default=None, description="from its git_repo_* section")
    commit: Optional[str] = Field(default=None, description="the commit the catalog's tests were last read from; null until it is first read")
    refreshed_at: Optional[datetime] = Field(default=None, description="when that commit was read")
    test_count: int = Field(description="the tests read from that commit")
    skipped_count: int = Field(description="tests and files that read could not use")
    removed_count: int = Field(description="its tests removed from the catalog")
    error: Optional[str] = Field(default=None, description="why the last refresh failed; null when it succeeded. The catalog keeps the tests of the commit it last read")
    retired: bool = Field(description="taken out of svs.catalog.repositories, so its tests were removed")
