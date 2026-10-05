"""The list of YARA QA signatures: rules in QA mode from the inventory, merged with what has been
recorded about their matches (docs/YARA_QA.md). Shared by the API (async) and `ace yara-qa list`
(sync): the statements here run on either kind of session, and the merge is plain Python.

A signature shows up when the rule is in QA mode now, whether or not it ever matched, or when
matches were recorded for it: a rule that has left QA mode (status not_qa) or left the repository
(status missing) keeps its counts and whatever samples have not expired yet.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Iterable, Optional

from sqlalchemy import Select, select

from saq.database.model import YaraQASignature
from saq.signatures.model import Signature, YaraInventory
from saq.signatures.yara_meta import is_qa_signature


def qa_signatures(inventory: YaraInventory) -> list[Signature]:
    """The inventoried rules that are in QA mode now."""
    return [signature for signature in inventory.by_uuid.values() if is_qa_signature(signature)]


class QAStatus(StrEnum):
    QA = "qa"            # the rule is in QA mode now
    NOT_QA = "not_qa"    # the rule exists but is no longer in QA mode
    MISSING = "missing"  # no rule with this uuid is loaded any more


class QASort(StrEnum):
    NAME = "name"
    LAST_MATCH = "last_match"
    MATCH_COUNT = "match_count"


@dataclass(frozen=True)
class VersionCounts:
    signature_version: str
    rule_name: str
    namespace: Optional[str]
    match_count: int
    stored_count: int
    first_match_at: datetime
    last_match_at: datetime


@dataclass
class QASignature:
    signature_uuid: str
    name: str
    status: QAStatus
    # from the inventory; None when the rule is missing
    enabled: Optional[bool] = None
    current_version: Optional[str] = None
    source_path: Optional[str] = None
    tags: tuple[str, ...] = ()
    # from the recorded matches (the most recent version's)
    namespace: Optional[str] = None
    match_count: int = 0
    stored_count: int = 0
    first_match_at: Optional[datetime] = None
    last_match_at: Optional[datetime] = None
    versions: list[VersionCounts] = field(default_factory=list)

    @property
    def version_count(self) -> int:
        return len(self.versions)


def version_rows_statement(signature_uuid: Optional[str] = None) -> Select:
    """Every counter row, or one signature's. Small: one row per version a QA rule matched under."""
    stmt = select(YaraQASignature)
    if signature_uuid is not None:
        stmt = stmt.where(YaraQASignature.signature_uuid == signature_uuid)
    return stmt


def _version_counts(row: YaraQASignature) -> VersionCounts:
    return VersionCounts(
        signature_version=row.signature_version, rule_name=row.rule_name, namespace=row.namespace,
        match_count=row.match_count, stored_count=row.stored_count,
        first_match_at=row.first_match_at, last_match_at=row.last_match_at)


def merge(inventory: YaraInventory, version_rows: Iterable[YaraQASignature]) -> list[QASignature]:
    """One QASignature per uuid that is in QA mode now or has recorded matches."""
    by_uuid: dict[str, QASignature] = {}

    def from_inventory(signature_uuid: str, signature: Optional[Signature], fallback_name: str) -> QASignature:
        if signature is None:
            return QASignature(signature_uuid=signature_uuid, name=fallback_name, status=QAStatus.MISSING)

        return QASignature(
            signature_uuid=signature_uuid, name=signature.name,
            status=QAStatus.QA if is_qa_signature(signature) else QAStatus.NOT_QA,
            enabled=signature.enabled, current_version=signature.version,
            source_path=signature.source_path, tags=signature.tags)

    for signature in qa_signatures(inventory):
        by_uuid[signature.uuid] = from_inventory(signature.uuid, signature, signature.name)

    for row in version_rows:
        summary = by_uuid.get(row.signature_uuid)
        if summary is None:
            summary = by_uuid[row.signature_uuid] = from_inventory(
                row.signature_uuid, inventory.by_uuid.get(row.signature_uuid), row.rule_name)

        summary.versions.append(_version_counts(row))

    for summary in by_uuid.values():
        summary.versions.sort(key=lambda v: v.last_match_at, reverse=True)
        if summary.versions:
            latest = summary.versions[0]
            summary.namespace = latest.namespace
            summary.match_count = sum(v.match_count for v in summary.versions)
            summary.stored_count = sum(v.stored_count for v in summary.versions)
            summary.first_match_at = min(v.first_match_at for v in summary.versions)
            summary.last_match_at = latest.last_match_at

    return list(by_uuid.values())


def filter_and_sort(signatures: list[QASignature], *, q: Optional[str] = None,
                    status: Optional[QAStatus] = None, has_matches: Optional[bool] = None,
                    sort: QASort = QASort.NAME, descending: bool = False) -> list[QASignature]:
    result = signatures
    if q:
        needle = q.strip().lower()
        result = [s for s in result if needle in s.name.lower() or needle in s.signature_uuid.lower()
                  or needle in (s.namespace or "").lower() or needle in (s.source_path or "").lower()]

    if status is not None:
        result = [s for s in result if s.status == status]

    if has_matches is not None:
        result = [s for s in result if (s.match_count > 0) == has_matches]

    match sort:
        case QASort.LAST_MATCH:
            key = lambda s: (s.last_match_at or datetime.min, s.name.lower())
        case QASort.MATCH_COUNT:
            key = lambda s: (s.match_count, s.name.lower())
        case _:
            key = lambda s: (s.name.lower(), s.signature_uuid)

    return sorted(result, key=key, reverse=descending)
