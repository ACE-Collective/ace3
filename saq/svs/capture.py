"""Capturing the files YARA rules matched on dispositioned alerts (docs/SVS.md, Part 2;
docs/SVS_SAMPLES.md).

The svs_yara_sample_capture module (saq/modules/svs.py) calls capture() for every candidate
candidates_from_root() finds, once the alert's disposition classifies tp or fp. A candidate is one
(file sha256, rule uuid) pair: a YARA detection on a file observable, with the structured details
the YARA module gives it (D-20). Detections from before those details existed are skipped (D-3), and
so are rules without a uuid (YR-7), since every such rule shares the built-in fallback signature.

What is kept, per (alert, sha256, rule uuid), in svs_yara_captures and the svs_samples CAS pool:
the file, the match record (the scan_results entry as the alert saved it), and what a replay needs
to scan the file as it was scanned: its path relative to the alert's files/ directory and its
yara_meta tags. The match record's strings went through the alert's JSON encoder when the alert was
saved, which decodes bytes lossily, so the record is for audit; a replay produces exact strings.

The row is inserted first, in a private session, then the CAS puts run, then the row is updated. A
capture that cannot store its bytes keeps its row as `missing`, so it is counted per rule and
retried on the alert's next dispositioned pass, and capture is idempotent on the row's unique key.
"""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Optional

import yara
import yara_scanner
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from saq.analysis.root import RootAnalysis
from saq.cas import Hold
from saq.cas.errors import ObjectDeleting, ObjectNotFound
from saq.cas.pool import CASPool
from saq.configuration.config import get_config
from saq.database.model import SVSYaraCapture
from saq.database.private_session import private_transaction
from saq.environment import get_global_runtime_settings
from saq.error.reporting import report_exception
from saq.json_encoding import _JSONEncoder
from saq.modules.file_analysis.yara import YaraScanResults_v3_4, is_yara_detection
from saq.observables.file import FileObservable
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.signatures.model import SIGNATURE_UUID_MAX_LENGTH
from saq.signatures.yara_inventory import get_yara_inventory
from saq.svs.constants import CaptureState, MissingReason
from saq.svs.samples import bytes_nodes_statement
from saq.yara_scanning.match_record import serialize_match_record, summarize_match_record

# cas_holds.holder_kind of every capture hold; the holder_id is the svs_yara_captures row id, which
# holds both the file and the match record
HOLDER_KIND = "svs_capture"

# column widths in svs_yara_captures
_RULE_NAME_MAX_LENGTH = 256
_NAMESPACE_MAX_LENGTH = 256
_FILE_PATH_MAX_LENGTH = 1024


class CaptureStatus(StrEnum):
    STORED = "stored"      # the file is now held for this capture
    ALREADY = "already"    # it already was
    MISSING = "missing"    # it could not be; the row says why


@dataclass(frozen=True)
class CaptureResult:
    status: CaptureStatus
    capture_id: int


@dataclass(frozen=True)
class CaptureCandidate:
    """One file a YARA rule matched on the alert, and what a replay needs to scan it again."""
    observable_uuid: str
    sha256: str
    rule_uuid: str
    rule_name: str
    namespace: Optional[str]
    signature_version: str
    file_path: str
    full_path: str
    yara_meta_tags: tuple[str, ...]
    # the scan_results entry as the alert saved it, or None if it is gone
    match_record: Optional[dict]

    def __str__(self) -> str:
        return f"{self.file_path} ({self.sha256}) for rule {self.rule_name} ({self.rule_uuid})"


def capture_hold(capture_id: int) -> Hold:
    return Hold(HOLDER_KIND, str(capture_id))


def _truncate(value: Optional[str], length: int) -> Optional[str]:
    return None if value is None else value[:length]


def _match_record(file_observable: FileObservable, rule: str, rule_uuid: str) -> Optional[dict]:
    """The file's scan_results entry for the rule, or None when the analysis or its details are
    gone (archive() drops the details of every analysis)."""
    analysis = file_observable.get_and_load_analysis(YaraScanResults_v3_4)
    if analysis is None or not isinstance(analysis.details, dict):
        return None

    for entry in analysis.details.get("scan_results") or []:
        if not isinstance(entry, dict):
            continue

        if entry.get("rule") == rule and (entry.get("meta") or {}).get("uuid") == rule_uuid:
            return entry

    return None


def candidates_from_root(root: RootAnalysis) -> list[CaptureCandidate]:
    """Every (file sha256, rule uuid) pair a YARA detection in the tree names. The first file
    observable with a given sha256 wins: the same bytes under two names in one alert are one
    capture."""
    candidates: dict[tuple[str, str], CaptureCandidate] = {}
    for node, detection in root.detection_points_by_node():
        if not isinstance(node, FileObservable) or not is_yara_detection(detection):
            continue

        details = detection.details
        rule_uuid = details["rule_uuid"]
        if not rule_uuid:
            logging.debug("yara rule %s has no uuid; its matches are not captured", details["rule"])
            continue

        if len(rule_uuid) > SIGNATURE_UUID_MAX_LENGTH:
            logging.warning("yara rule %s has a uuid longer than %s characters; its matches are not captured",
                            details["rule"], SIGNATURE_UUID_MAX_LENGTH)
            continue

        sha256 = details["sha256"].lower()
        key = (sha256, rule_uuid)
        if key in candidates:
            continue

        candidates[key] = CaptureCandidate(
            observable_uuid=node.uuid,
            sha256=sha256,
            rule_uuid=rule_uuid,
            rule_name=details["rule"],
            namespace=details["namespace"],
            signature_version=detection.signature_version,
            file_path=node.file_path,
            full_path=node.full_path,
            yara_meta_tags=tuple(node.yara_meta_tags),
            match_record=_match_record(node, details["rule"], rule_uuid))

    return list(candidates.values())


def _log_extra(alert_uuid: str, candidate: CaptureCandidate, **kwargs) -> dict:
    return {"alert_uuid": alert_uuid, "sha256": candidate.sha256, "rule_uuid": candidate.rule_uuid, **kwargs}


def _claim_row(alert_uuid: str, candidate: CaptureCandidate, now: datetime) -> tuple[int, Optional[SVSYaraCapture]]:
    """Insert the pending row, or return the existing one. Returns (id, existing row or None)."""
    try:
        with private_transaction() as session:
            row = SVSYaraCapture(
                alert_uuid=alert_uuid,
                observable_uuid=candidate.observable_uuid,
                sha256=candidate.sha256,
                rule_uuid=candidate.rule_uuid,
                rule_name=_truncate(candidate.rule_name, _RULE_NAME_MAX_LENGTH),
                namespace=_truncate(candidate.namespace, _NAMESPACE_MAX_LENGTH),
                signature_version=candidate.signature_version,
                file_path=_truncate(candidate.file_path, _FILE_PATH_MAX_LENGTH),
                yara_meta_tags=json.dumps(list(candidate.yara_meta_tags)),
                node=get_global_runtime_settings().saq_node,
                state=CaptureState.PENDING,
                created_at=now)
            session.add(row)
            session.flush()
            return row.id, None
    except IntegrityError:
        pass

    with private_transaction() as session:
        row = session.execute(
            select(SVSYaraCapture)
            .where(SVSYaraCapture.alert_uuid == alert_uuid,
                   SVSYaraCapture.sha256 == candidate.sha256,
                   SVSYaraCapture.rule_uuid == candidate.rule_uuid)).scalar_one()
        session.expunge(row)
        return row.id, row


def _set_row(capture_id: int, **values) -> None:
    with private_transaction() as session:
        session.execute(
            update(SVSYaraCapture).where(SVSYaraCapture.id == capture_id).values(**values)
            .execution_options(synchronize_session=False))


def _bytes_node(sha256: str) -> str:
    """The node a capture of these bytes was stored on first. A put writes the bytes to this node's
    backend, but a hold on an object another capture stored does not, so with a node-local pool a
    capture that only took a hold has its bytes wherever the first capture put them."""
    with private_transaction() as session:
        row = session.execute(bytes_nodes_statement([sha256]).limit(1)).first()

    return row.node if row is not None else get_global_runtime_settings().saq_node


def _rule_content_hash(rule_uuid: str) -> Optional[str]:
    try:
        signature = get_yara_inventory(get_config().svs.samples.inventory_refresh_seconds).by_uuid.get(rule_uuid)
    except Exception as e:
        logging.warning("unable to read the yara rule inventory: %s", e)
        return None

    return signature.content_hash if signature is not None else None


def _release(pool: CASPool, digests: list[str], hold: Hold) -> None:
    for digest in digests:
        try:
            pool.release(digest, hold)
        except ObjectNotFound:
            pass
        except Exception as e:
            logging.warning("unable to release svs capture hold %s on %s: %s", hold.holder_id, digest, e)


def capture(pool: CASPool, alert_uuid: str, candidate: CaptureCandidate) -> CaptureResult:
    """Capture one candidate of the alert: hold its file and its match record in the pool and record
    them in svs_yara_captures. Idempotent: a capture that is already stored is left as it is, and a
    pending or missing one is tried again."""
    now = datetime.now()
    capture_id, existing = _claim_row(alert_uuid, candidate, now)
    if existing is not None and existing.state == CaptureState.STORED:
        # a stored capture is retried only to add a match record it did not have
        if existing.missing_reason != MissingReason.MATCH_RECORD or candidate.match_record is None:
            return CaptureResult(CaptureStatus.ALREADY, capture_id)

    # a capture that was missing before and still is has already been reported
    was_missing = existing is not None and existing.state == CaptureState.MISSING
    hold = capture_hold(capture_id)
    held: list[str] = []
    node = get_global_runtime_settings().saq_node
    try:
        if os.path.exists(candidate.full_path):
            pool.put(candidate.full_path, hold=hold, digest=candidate.sha256)
        else:
            # the bytes may be in the pool already, from another alert
            try:
                node = _bytes_node(candidate.sha256)
                pool.hold(candidate.sha256, hold)
            except (ObjectNotFound, ObjectDeleting):
                _set_row(capture_id, state=CaptureState.MISSING, missing_reason=MissingReason.FILE)
                _log_missing(alert_uuid, candidate, MissingReason.FILE, was_missing)
                return CaptureResult(CaptureStatus.MISSING, capture_id)

        held.append(candidate.sha256)

        record_digest = None
        match_summary = None
        if candidate.match_record is not None:
            record_digest = pool.put(serialize_match_record(candidate.match_record), hold=hold)
            held.append(record_digest)
            match_summary = json.dumps(summarize_match_record(candidate.match_record), cls=_JSONEncoder)

        file_size = pool.stat(candidate.sha256).size
    except Exception as e:
        _release(pool, held, hold)
        _set_row(capture_id, state=CaptureState.MISSING, missing_reason=MissingReason.STORAGE)
        logging.error("unable to store svs capture %s of alert %s: %s", candidate, alert_uuid, e,
                      extra=_log_extra(alert_uuid, candidate, missing_reason=MissingReason.STORAGE.value))
        report_exception()
        return CaptureResult(CaptureStatus.MISSING, capture_id)

    values = dict(
        state=CaptureState.STORED,
        missing_reason=None if record_digest is not None else MissingReason.MATCH_RECORD,
        file_size=file_size,
        rule_content_hash=_rule_content_hash(candidate.rule_uuid),
        yara_python_version=yara.__version__,
        yara_scanner_version=yara_scanner.__version__,
        node=node,
        stored_at=now)
    if record_digest is not None:
        values.update(record_digest=record_digest, match_summary=match_summary)

    _set_row(capture_id, **values)

    if record_digest is None:
        logging.error("captured svs sample %s of alert %s without its match record (the alert's yara analysis is gone)",
                      candidate, alert_uuid,
                      extra=_log_extra(alert_uuid, candidate, missing_reason=MissingReason.MATCH_RECORD.value))

    newly_stored = existing is None or existing.state != CaptureState.STORED
    if candidate.signature_version == SIGNATURE_VERSION_UNKNOWN and newly_stored:
        # service_yara.git_repo_dirs is not set for the rule's repository
        logging.error("captured svs sample %s of alert %s with an unknown signature version", candidate, alert_uuid,
                      extra=_log_extra(alert_uuid, candidate))

    logging.info("captured svs sample %s of alert %s as %s", candidate, alert_uuid, capture_id,
                 extra=_log_extra(alert_uuid, candidate))
    return CaptureResult(CaptureStatus.STORED, capture_id)


def _log_missing(alert_uuid: str, candidate: CaptureCandidate, reason: MissingReason, was_missing: bool) -> None:
    extra = _log_extra(alert_uuid, candidate, missing_reason=reason.value)
    if was_missing:
        logging.info("svs sample %s of alert %s is still missing (%s)", candidate, alert_uuid, reason, extra=extra)
    else:
        logging.error("unable to capture svs sample %s of alert %s: its file is gone", candidate, alert_uuid, extra=extra)
