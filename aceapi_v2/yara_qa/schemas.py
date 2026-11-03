"""Schemas for the YARA QA results API (docs/YARA_QA.md)."""

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class QAPage(BaseModel, Generic[T]):
    """One page of a listing, with the total matching the filters."""
    data: list[T]
    total: int = Field(description="how many items match the filters, across all pages")
    limit: int
    offset: int


class QASignatureVersion(BaseModel):
    """What was recorded for one version of a signature (docs/YARA_QA.md, Versions)."""
    signature_version: str = Field(description="the rule's content hash (version_kind content), or for a match recorded without one the commit of the rule's repository, 'unknown' for rules outside a declared git repo (version_kind commit)")
    version_kind: str = Field(description="content or commit")
    first_commit: Optional[str] = Field(default=None, description="the commit of the rule's repository when this version first matched; null for versions recorded before content versions")
    last_commit: Optional[str] = Field(default=None, description="the commit of the rule's repository when this version last matched")
    rule_name: str = Field(description="the rule's name when it last matched under this version")
    namespace: Optional[str] = None
    match_count: int = Field(description="every match under this version, including those past the file cap")
    stored_count: int = Field(description="files stored under this version")
    first_match_at: datetime
    last_match_at: datetime


class QASignatureSummary(BaseModel):
    """A signature in QA mode now, or one with recorded QA matches."""
    signature_uuid: str
    name: str
    status: str = Field(description="qa: in QA mode now. not_qa: the rule exists but is no longer in QA mode. missing: no loaded rule has this uuid any more")
    enabled: Optional[bool] = Field(default=None, description="the rule's enabled meta; null when the rule is missing")
    current_version: Optional[str] = Field(default=None, description="the commit of the rule's repository as loaded now; null when the rule is missing")
    current_content_hash: Optional[str] = Field(default=None, description="the content hash of the rule as loaded now, which is the signature_version its matches are filed under; null when the rule is missing")
    source_path: Optional[str] = Field(default=None, description="the rule's file, relative to its repository")
    tags: list[str] = Field(default_factory=list)
    namespace: Optional[str] = Field(default=None, description="the yara namespace of the most recent match")
    match_count: int = Field(description="every QA match of this rule, across versions, including those past the file cap")
    stored_count: int = Field(description="files stored for this rule, across versions")
    version_count: int = Field(description="how many versions of the rule have matched")
    first_match_at: Optional[datetime] = None
    last_match_at: Optional[datetime] = None


class QASignaturePage(QAPage[QASignatureSummary]):
    inventory_error: Optional[str] = Field(default=None, description="set when the rule files could not all be read, in which case rules that never matched may be missing from the list")


class QASignatureDetail(QASignatureSummary):
    versions: list[QASignatureVersion] = Field(default_factory=list, description="most recent first")


class QAMatch(BaseModel):
    """One stored file."""
    id: int
    signature_uuid: str
    signature_version: str
    version_kind: str = Field(description="content or commit, as in the signature's versions")
    sha256: str
    file_name: str
    file_size: int
    hit_count: int = Field(description="how many times this file matched this version of the rule")
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime = Field(description="when the file is removed unless it matches again")
    node: str = Field(description="the node that stored the file")
    local: bool = Field(description="true when the file can be downloaded through this node: the pool is shared, or the file is on this node")
    root_uuid: str = Field(description="the analysis the file was found in")
    observable_uuid: str
    alert_uuid: Optional[str] = Field(default=None, description="set when that analysis became an alert")


class QAMatchDetail(QAMatch):
    match_summary: dict[str, Any] = Field(default_factory=dict, description="the rule, its meta and tags, and per string identifier how many times it matched and where first. The full record is at /matches/{id}/record")
