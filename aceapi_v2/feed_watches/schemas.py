"""Wire schemas for feed watches, their definitions, decisions, replays, labels and evaluation
(docs/FEED_WATCHES.md)."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

Mode = Literal["shadow", "delivering"]
Label = Literal["relevant", "not_relevant"]

QUESTION_ONLY_WARNING = ("this definition has no rule: every entry of the watch's feeds is sent to the LLM endpoint, "
                         "which with a hosted endpoint means leaving the network")


class Definition(BaseModel):
    name: str
    repository: str
    path: str
    commit: Optional[str] = None
    content_hash: Optional[str] = None
    yara: Optional[str] = None
    question: Optional[str] = None
    present: bool = Field(description="still in the definitions repositories")
    error: Optional[str] = Field(default=None, description="why it can't be used as it stands, if it can't")
    usable: bool = Field(description="a watch that names it matches")


class DefinitionPage(BaseModel):
    data: list[Definition]
    next_cursor: Optional[str] = None


class FeedRef(BaseModel):
    id: int
    name: str


class WatchRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    definition_name: str = Field(min_length=1, max_length=256)
    feed_ids: list[int] = Field(min_length=1)
    queue: str = Field(min_length=1, max_length=64, description="the alert queue it delivers to")
    mode: Mode = Field(default="shadow", description="shadow records decisions and delivers nothing")
    enabled: bool = True


class WatchUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    definition_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    feed_ids: Optional[list[int]] = Field(default=None, min_length=1)
    queue: Optional[str] = Field(default=None, min_length=1, max_length=64)
    mode: Optional[Mode] = None
    enabled: Optional[bool] = None


class Watch(BaseModel):
    id: int
    name: str
    definition_name: str
    definition: Optional[Definition] = None
    flag: Optional[str] = Field(default=None, description="why the watch matches nothing: its definition is missing or unusable")
    warning: Optional[str] = None
    queue: str
    mode: Mode
    enabled: bool
    version: int = Field(description="counts the edits of the watch")
    watch_version: str = Field(description="the version with the definition's current content hash")
    feeds: list[FeedRef]
    pending_decisions: int = 0
    failed_decisions: int = 0
    created_by: Optional[str] = None
    created_at: datetime
    updated_by: Optional[str] = None
    updated_at: datetime


class WatchPage(BaseModel):
    data: list[Watch]
    next_cursor: Optional[str] = None


class EntryRef(BaseModel):
    id: int
    feed_id: int
    title: Optional[str] = None
    link: Optional[str] = None
    published_at: Optional[datetime] = None
    first_seen_at: datetime


class Decision(BaseModel):
    id: int
    kind: str
    entry: EntryRef
    watch_id: Optional[int] = None
    watch_version: Optional[str] = None
    definition_name: Optional[str] = None
    status: str
    decision: Optional[str] = None
    excerpt: Optional[str] = None
    rationale: Optional[str] = None
    yara_matched: Optional[bool] = None
    yara_excerpt: Optional[str] = None
    yara_field: Optional[str] = None
    attempts: int
    last_error: Optional[str] = None
    model: str
    response_model: Optional[str] = None
    prompt_hash: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: Optional[int] = None
    truncated: bool
    alert_uuid: Optional[str] = Field(default=None, description="the alert that delivered it")
    created_at: datetime
    decided_at: Optional[datetime] = None


class DecisionPage(BaseModel):
    data: list[Decision]
    next_cursor: Optional[str] = None


class ReplayRequest(BaseModel):
    """A draft definition; it is never saved anywhere a watch reads it."""
    yara: Optional[str] = Field(default=None, max_length=1024 * 1024)
    question: Optional[str] = Field(default=None, max_length=16384)
    feed_ids: list[int] = Field(min_length=1)
    watch_id: Optional[int] = Field(default=None, description="the watch the page labels entries for")


class ReplayCounts(BaseModel):
    entries: int = 0
    rule_matched: int = 0
    asked: int = 0
    pending: int = 0
    failed: int = 0
    match: int = 0
    no_match: int = 0
    insufficient_evidence: int = 0


class Replay(BaseModel):
    id: int
    state: str
    error: Optional[str] = None
    yara: Optional[str] = None
    question: Optional[str] = None
    feed_ids: list[int]
    watch_id: Optional[int] = None
    warning: Optional[str] = None
    counts: ReplayCounts
    created_by: Optional[str] = None
    created_at: datetime
    finished_at: Optional[datetime] = None


class ReplayResult(BaseModel):
    entry: EntryRef
    text: str
    yara_matched: Optional[bool] = None
    yara_excerpt: Optional[str] = None
    yara_field: Optional[str] = None
    status: Optional[str] = Field(default=None, description="the question's decision status; null when it was not asked")
    decision: Optional[str] = None
    excerpt: Optional[str] = None
    rationale: Optional[str] = None
    last_error: Optional[str] = None
    matched: Optional[bool] = Field(default=None, description="the draft as a whole would alert; null while pending")
    label: Optional[Label] = Field(default=None, description="the label for the replay's watch")


class ReplayResultPage(BaseModel):
    data: list[ReplayResult]
    next_cursor: Optional[str] = None


class LabelRequest(BaseModel):
    label: Label


class Score(BaseModel):
    predictor: str = Field(description="decision: what the watch decided; yara_only: its rule alone")
    evaluated: int
    true_positives: int
    false_alerts: int
    missed_relevant: int
    true_negatives: int
    insufficient_evidence: int
    pending: int
    failed: int


class Configuration(BaseModel):
    watch_version: str
    watch_row_version: Optional[int] = None
    definition_hash: str
    model: str
    prompt_hash: str
    scores: list[Score]
    questions_asked: int
    avg_latency_ms: Optional[float] = None
    max_latency_ms: Optional[int] = None
    prompt_tokens: int
    completion_tokens: int
    response_models: list[str]


class Evaluation(BaseModel):
    watch_id: int
    labeled: int
    relevant: int
    not_relevant: int
    configurations: list[Configuration]
