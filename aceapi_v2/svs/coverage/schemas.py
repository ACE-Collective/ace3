"""Wire schemas for ATT&CK coverage (/svs/coverage)."""

from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, Field


class CoverageRow(BaseModel):
    """Coverage of one ATT&CK technique on one platform, as of the last refresh."""

    technique: str = Field(description="the ATT&CK technique id, e.g. T1059 or T1059.001")
    platform: str = Field(description="an ATT&CK platform slug: windows, linux, macos, iaas, ...")
    parent: Optional[str] = Field(default=None, description="the parent technique of a sub-technique")
    is_subtechnique: bool
    technique_name: Optional[str] = None
    tactics: list[str] = Field(description="the technique's tactic ids (TA0002) in the pinned release")
    catalog_status: str = Field(description="active, deprecated, or unknown (not in the pinned release)")
    attack_platform: bool = Field(description="ATT&CK lists the platform for the technique; otherwise only a test "
                                              "brought the row")
    state: str = Field(description="failing, stale, validated, manual, untested or none: the worst of what counts "
                                   "toward the technique and its sub-techniques on the platform")
    own_state: str = Field(description="the same, leaving the sub-techniques out")
    tests_total: int = Field(description="tests counted toward state, the sub-techniques' included")
    tests_validated: int
    tests_failing: int
    tests_stale: int
    manual_signatures: int = Field(description="signatures whose mitre: tag counts toward state")
    measured_signatures: int = Field(description="signatures expected of the counted tests on the platform")
    last_reviewed_at: Optional[datetime] = Field(default=None, description="the latest review of a run that counts")
    state_changed_at: datetime
    first_seen_at: datetime
    retired_at: Optional[datetime] = Field(default=None, description="when the computation stopped producing the "
                                                                     "row; it is never deleted")
    updated_at: datetime = Field(description="when the row last changed; the changed_since key")


class CoveragePage(BaseModel):
    data: list[CoverageRow]
    next_cursor: Optional[str] = None


class PlatformCounts(BaseModel):
    platform: str
    rows: int
    states: dict[str, int] = Field(description="rows per state, every state named")
    own_states: dict[str, int] = Field(description="rows per own_state, every state named")


class CoverageSummary(BaseModel):
    """The rows the filters match, counted, and what the last refresh did."""

    rows: int
    states: dict[str, int] = Field(description="rows per state, every state named")
    own_states: dict[str, int] = Field(description="rows per own_state, every state named")
    platforms: list[PlatformCounts] = Field(description="the same per platform, in the release's platform order")
    attack_release: Optional[str] = Field(default=None, description="the ATT&CK release of the last refresh")
    refreshed_at: Optional[datetime] = Field(default=None, description="when the last refresh completed; null "
                                                                       "before the first")
    duration_ms: Optional[int] = None
    unknown_tags: int = Field(default=0, description="mitre: tags naming an id the release doesn't have")
    ignored_tags: int = Field(default=0, description="mitre: tags that aren't technique ids (templated, tactics)")
    error: Optional[str] = Field(default=None, description="why the latest refresh failed; null once one completes")


class CoverageTest(BaseModel):
    """One catalog test on one platform, as it counts toward the technique's coverage there."""

    guid: str
    name: str
    test_technique: str = Field(description="the technique as the test's atomic file names it")
    technique: str = Field(description="the technique it counts toward (a revoked id becomes its successor)")
    platform: str
    test_state: str = Field(description="never_run (no run or decision on the platform), awaiting_review, "
                                        "no_expectations, failing, stale or validated")
    contribution: str = Field(description="what it counts as toward the row: failing, stale, validated or untested")
    last_reviewed_run_id: Optional[str] = None
    last_reviewed_at: Optional[datetime] = None
    expected_signatures: list[str] = Field(default_factory=list, description="signature uuids expected of it on the "
                                                                             "platform that no ignore applies to")


class TestPlatform(BaseModel):
    __test__ = False

    guid: str
    platform: str


class MeasuredSignature(BaseModel):
    """A signature expected of the technique's tests: a measured mapping."""

    signature_uuid: str
    name: Optional[str] = None
    family: Optional[str] = None
    tests: list[TestPlatform] = Field(description="the (test, platform) pairs that expect it")


class ManualSignature(BaseModel):
    """A signature's mitre: tag naming the technique or a sub-technique: a manual mapping."""

    signature_uuid: str
    name: Optional[str] = None
    family: str = Field(description="hunt or yara")
    declared: str = Field(description="the technique id the tag names")
    technique: str = Field(description="the technique it counts toward (a revoked id becomes its successor)")
    counts: bool
    reason: Optional[str] = Field(default=None, description="why it doesn't count: not_counting (disabled, or a YARA "
                                                            "rule in QA mode) or unknown_technique")


class RemovedTest(BaseModel):
    guid: str
    name: str
    technique: str
    removed_at: Optional[datetime] = None


class TechniqueCoverage(BaseModel):
    """A technique's coverage: its rows as of the last refresh, and what counts toward them now."""

    requested: str = Field(description="the id asked for")
    technique: str = Field(description="the technique answered for: the requested id, or its successor when revoked")
    name: Optional[str] = None
    parent: Optional[str] = None
    is_subtechnique: bool
    catalog_status: str
    tactics: list[str] = Field(default_factory=list)
    attack_release: str = Field(description="the pinned ATT&CK release")
    refreshed_at: Optional[datetime] = Field(default=None, description="when the rows were last refreshed; the tests "
                                                                       "and signatures below are read now")
    rows: list[CoverageRow] = Field(description="the technique's rows, retired ones included")
    sub_technique_rows: list[CoverageRow] = Field(description="its sub-techniques' rows, retired ones included")
    tests: list[CoverageTest] = Field(description="the tests of the technique and its sub-techniques, per platform")
    measured_signatures: list[MeasuredSignature]
    manual_signatures: list[ManualSignature]
    manual_signatures_error: Optional[str] = Field(default=None, description="why the signature tags couldn't be "
                                                                             "read; manual_signatures is then empty")
    removed_tests: list[RemovedTest] = Field(description="tests removed from their repository; they don't count")


class CoverageSnapshotRow(BaseModel):
    """A coverage row as it was on one day."""

    snapshot_date: date = Field(description="the UTC day")
    technique: str
    platform: str
    attack_release: str
    parent: Optional[str] = None
    is_subtechnique: bool
    state: str
    own_state: str
    tests_total: int
    tests_validated: int
    tests_failing: int
    tests_stale: int
    manual_signatures: int
    measured_signatures: int
    updated_at: datetime = Field(description="when the row was written; a second snapshot the same day rewrites it")


class CoverageHistoryPage(BaseModel):
    data: list[CoverageSnapshotRow]
    next_cursor: Optional[str] = None


class PeriodCounts(BaseModel):
    period: str = Field(description="the day (2026-10-16) or the month (2026-10)")
    snapshot_date: date = Field(description="the snapshot counted: the day's, or the month's last")
    rows: int
    states: dict[str, int] = Field(description="rows per state, every state named")
    own_states: dict[str, int] = Field(description="rows per own_state, every state named")


class CoverageHistoryCounts(BaseModel):
    group: str
    data: list[PeriodCounts] = Field(description="oldest first")


COVERAGE_CSV_FIELDS = tuple(CoverageRow.model_fields)
COVERAGE_HISTORY_CSV_FIELDS = tuple(CoverageSnapshotRow.model_fields)
