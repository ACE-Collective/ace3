"""SVS YARA validation schemas for ACE API v2 (docs/SVS_API.md, *Validations*)."""

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from aceapi_v2.detection_points.schemas import VerdictSource
from aceapi_v2.svs.samples.schemas import Label

ValidationStateName = Literal["queued", "running", "completed", "failed"]
Outcome = Literal["match", "miss", "error"]

# a full commit id: sha1 (40) or sha256 (64) object format. Abbreviations are refused so that two
# requests for one commit are recognized as the same
_COMMIT_PATTERN = r"^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"


class ValidationRequest(BaseModel):
    """What the signature repository's CI asks for: validate head_sha against base_sha."""
    repository: str = Field(min_length=1, max_length=256, description="a git_repo_<name> section named in svs.yara.repositories")
    base_sha: str = Field(pattern=_COMMIT_PATTERN, description="the full id of the commit to compare against: the pull request's merge base")
    head_sha: str = Field(pattern=_COMMIT_PATTERN, description="the full id of the commit to validate")
    branch: str = Field(min_length=1, max_length=256, description="the branch head_sha is on")
    pr_url: Optional[str] = Field(default=None, max_length=2048, pattern=r"^https?://", description="the pull request, for the report's link back")

    @field_validator("base_sha", "head_sha")
    @classmethod
    def _lowercase(cls, value: str) -> str:
        return value.lower()


class RuleCount(BaseModel):
    rule_uuid: str
    rule_name: str
    count: int = Field(description="how many samples of the category the rule has in this validation")


class CompileProblem(BaseModel):
    file: str = Field(description="the rule file, relative to the repository root")
    error: str


class ValidationStatus(BaseModel):
    """A validation as the signature repository's CI sees it (svs:validate): its state, counts, and
    rule names and uuids. It never carries a sample's sha256, file name or content."""
    uuid: str
    state: ValidationStateName
    error: Optional[str] = Field(default=None, description="why a failed validation could not run")
    repository: str
    base_sha: str
    head_sha: str
    branch: str
    pr_url: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    diffed: Optional[bool] = Field(default=None, description="false when either commit's ruleset would not load, so nothing was compared")
    counts: Optional[dict[str, int]] = Field(default=None, description="pairs (sample, rule uuid) per category, every category included; set once completed")
    rules: dict[str, list[RuleCount]] = Field(default_factory=dict, description="the rules with samples in each listed category, most samples first")
    compile_errors: list[CompileProblem] = Field(default_factory=list, description="the head's rule files that do not compile; their rules are dropped")
    ruleset_error: Optional[str] = Field(default=None, description="set when the head's rules would not load together: production keeps its previous rules")
    report_path: str = Field(description="the report in the ACE GUI, relative to the GUI's host")


class ValidationRow(BaseModel):
    """One validation in the listing (signature:read). Timestamps are UTC."""
    uuid: str
    repository: str
    base_sha: str
    head_sha: str
    branch: str
    pr_url: Optional[str] = None
    state: ValidationStateName
    requested_by: Optional[str] = Field(default=None, description="the user whose key requested it")
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    diffed: Optional[bool] = None
    regressions: Optional[int] = Field(default=None, description="regression + regression_unconfirmed")
    new_fps: Optional[int] = Field(default=None, description="new_fp + new_fp_other_rule")
    compile_errors: Optional[int] = Field(default=None, description="the head's rule files that do not compile, plus one if its ruleset would not load")
    counts: Optional[dict[str, int]] = None
    updated_at: datetime


class ValidationListPage(BaseModel):
    data: list[ValidationRow]
    next_cursor: Optional[str] = Field(
        default=None, description="pass as ?cursor= with the same filters for the next page; null on the last page")


# the CSV export's columns, in order; the counts are their own columns
VALIDATION_ROW_CSV_FIELDS = tuple(name for name in ValidationRow.model_fields if name != "counts")


class ValidationDetail(ValidationRow):
    """One validation with its report (signature:read)."""
    attempts: int = Field(description="how many times a worker has claimed it")
    claimed_by: Optional[str] = Field(default=None, description="the node that ran (or runs) it")
    corpus_version: Optional[str] = Field(default=None, description="what the samples and their labels were when it ran")
    engine_fingerprint: Optional[str] = Field(default=None, description="what decided its results besides the corpus and the commits")
    report: Optional[dict[str, Any]] = Field(
        default=None,
        description="how each commit compiled, the rules added, removed and changed, the rules that "
                    "cannot be tested, the samples skipped and the timings; its listed pairs are "
                    "GET …/results")


class ValidationResultRow(BaseModel):
    """One (sample, rule uuid) pair the report lists, with the sample's label when it ran."""
    id: int
    sha256: str
    rule_uuid: str
    rule_name: str
    namespace: Optional[str] = None
    label: Optional[Label] = None
    label_source: Optional[VerdictSource] = None
    base: Outcome = Field(description="the outcome under base_sha: match (the rule would make a detection), miss or error")
    head: Outcome
    raw_base: bool = Field(description="whether the rule matched under base at all, before enabled and the qa/no_alert modifiers")
    raw_head: bool
    category: str
    note: Optional[str] = None


class ValidationResultPage(BaseModel):
    data: list[ValidationResultRow]
    next_cursor: Optional[str] = Field(
        default=None, description="pass as ?cursor= with the same filters for the next page; null on the last page")


VALIDATION_RESULT_CSV_FIELDS = tuple(ValidationResultRow.model_fields)
