"""The analyst actions on an SVS sample (docs/SVS_SAMPLES.md, *Actions*; docs/SVS.md, Part 2,
*Report and baseline*).

- **Relabel**, **Reset** and **Confirm** never store a label: a label is derived from the verdicts
  of the sample's contributing detections (saq.svs.labels), so these write, clear or confirm the
  explicit verdicts on those detections through saq.detection_verdicts.store, all in one
  transaction. Detections that cannot take an analyst's verdict (on an FP alert, an unclassified
  alert, a test alert) are skipped and reported with the reason.
- **Retire** marks a (sha256, rule uuid) pair as no longer expected to match its rule, so YARA
  validation only counts it. Unretiring is soft.
- **Delete** removes a file from SVS entirely, for legal or privacy requests: every capture of the
  sha256 (for every rule) and its retirements go, the file's bytes are purged from the pool, and an
  audit row in svs_sample_deletions is kept, which also keeps capture from storing the file again.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from saq.auth import ApiAuthResult
from saq.cas import get_cas
from saq.cas.errors import LegalHoldActive
from saq.cas.pool import CASPool
from saq.configuration.config import get_config
from saq.database.model import Alert, SVSSampleDeletion, SVSSampleRetirement, SVSValidationResult, SVSYaraCapture
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.detection_verdicts.constants import SOURCE_EXPLICIT, SOURCE_INHERITED_MULTI, VERDICT_TP
from saq.detection_verdicts.store import SkipCause, VerdictBatch, VerdictNotAllowed, set_verdicts, verdict_refusal
from saq.environment import get_global_runtime_settings
from saq.logging import log_audit
from saq.svs.samples import bytes_nodes, contributing_detections, get_captures, get_sample, is_local, to_utc_naive
from saq.svs.storage import purge_deleted_file, release_capture_holds


class SampleNotFound(Exception):
    """There is no such sample (no capture of the pair, or of the sha256)."""


class NotRetired(Exception):
    """The sample is not retired."""


class WrongNode(Exception):
    """The sample's bytes are on another node's local pool, so only that node can delete them."""

    def __init__(self, node: str):
        super().__init__(f"the sample's file is stored on node {node}")
        self.node = node


def _require_reason(reason: Optional[str]) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required")
    return reason


#
# relabel, reset, confirm
#

@dataclass(frozen=True)
class SkippedVerdict:
    alert_uuid: str
    content_hash: str
    reason: str


@dataclass(frozen=True)
class LabelChange:
    """What a relabel, reset or confirm did, and the sample's label afterwards."""
    changed: int
    unchanged: int
    skipped: list[SkippedVerdict] = field(default_factory=list)
    label: Optional[str] = None
    label_source: Optional[str] = None


def _targets(sha256: str, rule_uuid: str, source: Optional[str] = None) -> tuple[list[tuple[int, str]], dict[int, str]]:
    """The (alert_id, content_hash) of the sample's contributing detections (only those whose
    verdict source is `source`, when given), and each alert's uuid. Raises SampleNotFound."""
    captures = get_captures(sha256, rule_uuid)
    if not captures:
        raise SampleNotFound(f"no sample {sha256} for rule {rule_uuid}")

    targets: dict[tuple[int, str], None] = {}
    alert_uuids: dict[int, str] = {}
    for detections in contributing_detections(capture.id for capture in captures).values():
        for detection in detections:
            if source is None or detection["verdict_source"] == source:
                targets[(detection["alert_id"], detection["content_hash"])] = None
                alert_uuids[detection["alert_id"]] = detection["alert_uuid"]

    return list(targets), alert_uuids


def _label_change(sha256: str, rule_uuid: str, batch: VerdictBatch, alert_uuids: dict[int, str]) -> LabelChange:
    if batch.changed == 0 and batch.unchanged == 0:
        # nothing could be written, and something other than a race says why
        refusals = sorted({skipped.reason for skipped in batch.skipped
                           if skipped.cause in (SkipCause.ALERT, SkipCause.DETECTION)})
        if refusals:
            raise VerdictNotAllowed("no contributing detection of the sample can take the verdict: " + "; ".join(refusals))

    sample = get_sample(sha256, rule_uuid) or {}
    return LabelChange(
        changed=batch.changed,
        unchanged=batch.unchanged,
        skipped=[SkippedVerdict(alert_uuids[skipped.alert_id], skipped.content_hash, skipped.reason)
                 for skipped in batch.skipped],
        label=sample.get("label"),
        label_source=sample.get("label_source"))


def _require_targets(targets: list) -> None:
    if not targets:
        raise VerdictNotAllowed(NO_DETECTION_LEFT)


NO_DETECTION_LEFT = "the sample has no contributing detection left: the alerts it was captured from were deleted"


def relabel_refusal(sha256: str, rule_uuid: str, detections: Optional[dict[int, list[dict]]] = None) -> Optional[str]:
    """Why relabel would be refused for the sample (no contributing detection can take a verdict),
    or None when it would write at least one: so the GUI offers it only when it works.
    detections is contributing_detections() of its captures, when the caller has it."""
    if detections is None:
        detections = contributing_detections(capture.id for capture in get_captures(sha256, rule_uuid))
    rows = [row for capture_rows in detections.values() for row in capture_rows]
    if not rows:
        return NO_DETECTION_LEFT

    dispositions = dict(get_db().execute(select(Alert.id, Alert.disposition)
                                         .where(Alert.id.in_({row["alert_id"] for row in rows}))).all())
    reasons = set()
    for row in rows:
        if row["node_kind"] is None:
            reason = "the detection predates detection identity; re-sync the alert first"
        else:
            reason = verdict_refusal(dispositions.get(row["alert_id"]))
        if reason is None:
            return None
        reasons.add(reason)
    return "no contributing detection of the sample can take the verdict: " + "; ".join(sorted(reasons))


def relabel(sha256: str, rule_uuid: str, verdict: str, user_id: int, *,
            auth: Optional[ApiAuthResult] = None) -> LabelChange:
    """Stores the explicit verdict ('tp' or 'fp') on every contributing detection of the sample
    that can take one. Raises SampleNotFound, or VerdictNotAllowed when none can."""
    targets, alert_uuids = _targets(sha256, rule_uuid)
    _require_targets(targets)
    batch = set_verdicts(targets, verdict, user_id, auth=auth)
    _log_audit("svs sample relabeled", sha256, rule_uuid, user_id, auth, verdict=verdict, changed=batch.changed)
    return _label_change(sha256, rule_uuid, batch, alert_uuids)


def reset_label(sha256: str, rule_uuid: str, user_id: int, *, auth: Optional[ApiAuthResult] = None) -> LabelChange:
    """Clears the explicit verdicts on the sample's contributing detections, so its label is
    derived from its alerts' dispositions again. Only explicit detections are targeted, so one on
    an FP alert (whose override, if any, is masked) is not listed as skipped. Nothing to reset is
    not an error."""
    targets, alert_uuids = _targets(sha256, rule_uuid, SOURCE_EXPLICIT)
    batch = set_verdicts(targets, None, user_id, auth=auth)
    if targets:
        _log_audit("svs sample label reset", sha256, rule_uuid, user_id, auth, changed=batch.changed)
    return _label_change(sha256, rule_uuid, batch, alert_uuids)


def confirm(sha256: str, rule_uuid: str, user_id: int, *, auth: Optional[ApiAuthResult] = None) -> LabelChange:
    """Confirms the sample's unconfirmed (inherited_multi) TP detections: an explicit TP on each,
    which upgrades their source without changing the verdict. Nothing to confirm is not an error."""
    targets, alert_uuids = _targets(sha256, rule_uuid, SOURCE_INHERITED_MULTI)
    batch = set_verdicts(targets, VERDICT_TP, user_id, only_source=SOURCE_INHERITED_MULTI, auth=auth)
    if targets:
        _log_audit("svs sample confirmed", sha256, rule_uuid, user_id, auth, changed=batch.changed)
    return _label_change(sha256, rule_uuid, batch, alert_uuids)


#
# retire
#

def _sample_exists(sha256: str, rule_uuid: str) -> bool:
    return get_db().execute(
        select(SVSYaraCapture.id)
        .where(SVSYaraCapture.sha256 == sha256, SVSYaraCapture.rule_uuid == rule_uuid)
        .limit(1)).first() is not None


def _retirement(session, sha256: str, rule_uuid: str, *, lock: bool = False) -> Optional[SVSSampleRetirement]:
    statement = select(SVSSampleRetirement).where(
        SVSSampleRetirement.sha256 == sha256, SVSSampleRetirement.rule_uuid == rule_uuid)
    if lock:
        statement = statement.with_for_update()
    return session.execute(statement).scalar_one_or_none()


def get_retirement(sha256: str, rule_uuid: str) -> Optional[SVSSampleRetirement]:
    """The pair's retirement row, active or not, or None."""
    return _retirement(get_db(), sha256, rule_uuid)


def retire(sha256: str, rule_uuid: str, user_id: int, reason: str, *,
           auth: Optional[ApiAuthResult] = None) -> SVSSampleRetirement:
    """Retires the sample for its rule. Retiring a retired sample changes nothing. Raises
    SampleNotFound, or ValueError without a reason."""
    reason = _require_reason(reason)
    session = get_db()
    try:
        if not _sample_exists(sha256, rule_uuid):
            raise SampleNotFound(f"no sample {sha256} for rule {rule_uuid}")

        row = _retirement(session, sha256, rule_uuid, lock=True)
        if row is not None and row.unretired_at is None:
            session.commit()
            return row

        now = datetime.now()
        if row is None:
            row = SVSSampleRetirement(sha256=sha256, rule_uuid=rule_uuid)
            session.add(row)

        row.reason = reason
        row.retired_by = user_id
        row.retired_at = now
        row.unretired_by = None
        row.unretired_at = None
        session.commit()
    except IntegrityError:
        # retired by someone else at the same moment
        session.rollback()
        return _retirement(session, sha256, rule_uuid)
    except Exception:
        session.rollback()
        raise

    _log_audit("svs sample retired", sha256, rule_uuid, user_id, auth, reason=reason)
    return row


def unretire(sha256: str, rule_uuid: str, user_id: int, *, auth: Optional[ApiAuthResult] = None) -> SVSSampleRetirement:
    """Unretires the sample: it is expected to match its rule again. Raises NotRetired."""
    session = get_db()
    try:
        row = _retirement(session, sha256, rule_uuid, lock=True)
        if row is None or row.unretired_at is not None:
            raise NotRetired(f"sample {sha256} is not retired for rule {rule_uuid}")

        row.unretired_by = user_id
        row.unretired_at = datetime.now()
        session.commit()
    except Exception:
        session.rollback()
        raise

    _log_audit("svs sample unretired", sha256, rule_uuid, user_id, auth)
    return row


def retired_pairs() -> frozenset[tuple[str, str]]:
    """The (sha256, rule uuid) pairs that are retired now."""
    rows = get_db().execute(
        select(SVSSampleRetirement.sha256, SVSSampleRetirement.rule_uuid)
        .where(SVSSampleRetirement.unretired_at.is_(None))).all()
    return frozenset((row.sha256, row.rule_uuid) for row in rows)


#
# delete
#

def get_deletion(sha256: str) -> Optional[SVSSampleDeletion]:
    return get_db().execute(select(SVSSampleDeletion).where(SVSSampleDeletion.sha256 == sha256)).scalar_one_or_none()


def _pool() -> CASPool:
    return get_cas().pool(get_config().svs.samples.pool)


def _record_deletion(sha256: str, user_id: int, reason: str, node: str) -> None:
    """Commits the audit row, unless there is one; from here on capture refuses the sha256."""
    try:
        with private_transaction() as session:
            rule_uuids = session.execute(
                select(SVSYaraCapture.rule_uuid).where(SVSYaraCapture.sha256 == sha256).distinct()).scalars().all()
            capture_count = session.execute(
                select(func.count()).select_from(SVSYaraCapture).where(SVSYaraCapture.sha256 == sha256)).scalar_one()
            session.add(SVSSampleDeletion(
                sha256=sha256, deleted_by=user_id, reason=reason, deleted_at=datetime.now(),
                rule_uuids=json.dumps(sorted(rule_uuids)), capture_count=capture_count, node=node))
    except IntegrityError:
        # deleted by someone else at the same moment: theirs is the audit row
        pass


def _remove_rows(sha256: str) -> list[tuple[int, Optional[str]]]:
    """Deletes every capture, retirement and validation result of the sha256. Returns the (id, record_digest) of the
    captures removed."""
    with private_transaction() as session:
        captures = [(row.id, row.record_digest) for row in session.execute(
            select(SVSYaraCapture.id, SVSYaraCapture.record_digest)
            .where(SVSYaraCapture.sha256 == sha256)
            .with_for_update())]
        session.execute(delete(SVSYaraCapture).where(SVSYaraCapture.sha256 == sha256)
                        .execution_options(synchronize_session=False))
        session.execute(delete(SVSSampleRetirement).where(SVSSampleRetirement.sha256 == sha256)
                        .execution_options(synchronize_session=False))
        # a validation report never names a deleted file
        session.execute(delete(SVSValidationResult).where(SVSValidationResult.sha256 == sha256)
                        .execution_options(synchronize_session=False))
        return captures


def delete_sample(sha256: str, user_id: int, reason: str, *, actor: Optional[str],
                  auth: Optional[ApiAuthResult] = None) -> SVSSampleDeletion:
    """Deletes the file from SVS: every capture of the sha256 (for every rule) and its retirements,
    the holds on its match records (CAS GC collects them once nothing else holds them), and the
    file's bytes, purged from the pool. The audit row is committed first and kept.

    Idempotent: deleting a deleted sample retries the purge if it did not finish, and returns the
    audit row. Raises SampleNotFound, ValueError without a reason, WrongNode when the bytes are on
    another node's local pool, and LegalHoldActive when the file is under legal hold."""
    reason = _require_reason(reason)
    session = get_db()
    existing = get_deletion(sha256)
    node = existing.node if existing is not None else bytes_nodes([sha256]).get(sha256)
    captured = _is_captured(sha256)
    session.commit()
    if existing is None and not captured:
        raise SampleNotFound(f"no sample {sha256}")

    if node is None:
        # no capture has the bytes (every one is missing): nothing to purge but the rows
        node = get_global_runtime_settings().saq_node

    if not is_local(node):
        raise WrongNode(node)

    pool = _pool()
    if any(hold.is_legal for hold in pool.holds(sha256)):
        raise LegalHoldActive(pool.name, sha256)

    if existing is None:
        _record_deletion(sha256, user_id, reason, node)

    captures = _remove_rows(sha256)
    for capture_id, record_digest in captures:
        if record_digest is not None:
            release_capture_holds(pool, capture_id, [record_digest])

    if purge_deleted_file(pool, sha256, reason=f"svs sample deletion: {reason}", actor=actor):
        with private_transaction() as session:
            session.execute(
                update(SVSSampleDeletion)
                .where(SVSSampleDeletion.sha256 == sha256, SVSSampleDeletion.purged_at.is_(None))
                .values(purged_at=datetime.now())
                .execution_options(synchronize_session=False))

    # a fresh transaction, to see what the private ones wrote
    session.commit()
    deletion = get_deletion(sha256)
    log_audit("svs sample deleted", auth=auth, sha256=sha256, rule_uuids=json.loads(deletion.rule_uuids),
              capture_count=len(captures), purged=deletion.purged_at is not None, actor_user_id=user_id, reason=reason)
    return deletion


def _is_captured(sha256: str) -> bool:
    return get_db().execute(select(SVSYaraCapture.id).where(SVSYaraCapture.sha256 == sha256).limit(1)).first() is not None


def _log_audit(message: str, sha256: str, rule_uuid: str, user_id: int, auth: Optional[ApiAuthResult], **extra) -> None:
    # actor_user_id is the user the action is recorded against, even for a caller that passes no auth
    log_audit(message, auth=auth, sha256=sha256, rule_uuid=rule_uuid, actor_user_id=user_id, **extra)


#
# the deletion audit (GET /api/v2/svs/samples/deletions)
#

def deletions_page(changed_since: Optional[datetime], after: Optional[tuple[datetime, int]],
                   limit: int) -> list[SVSSampleDeletion]:
    """Deletion audit rows in (updated_at, id) order, after the keyset `after`, changed at or after
    changed_since when it is given, at most `limit` of them."""
    statement = select(SVSSampleDeletion)
    if changed_since is not None:
        statement = statement.where(SVSSampleDeletion.updated_at >= to_utc_naive(changed_since))
    if after is not None:
        updated_at, row_id = after
        statement = statement.where(or_(
            SVSSampleDeletion.updated_at > updated_at,
            and_(SVSSampleDeletion.updated_at == updated_at, SVSSampleDeletion.id > row_id)))
    statement = statement.order_by(SVSSampleDeletion.updated_at, SVSSampleDeletion.id).limit(limit)
    return list(get_db().execute(statement).scalars())
