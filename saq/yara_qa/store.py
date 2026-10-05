"""Storing the files matched by YARA rules in QA mode (docs/YARA_QA.md).

record_qa_match() is called by the yara scanner service's qa recorder (saq/yara_scanning/qa.py) for
every match of a rule whose `modifiers` include `qa`, off the scanning path: the scanning workers
only spool the match (docs/YARA_SCANNER.md). It keeps the matched file and the full match record
in the yara_qa CAS pool and indexes them in yara_qa_matches, subject to two caps: at most
yara_qa.max_files_per_version distinct files per (signature uuid, signature version), and at most
yara_qa.max_files_per_signature per uuid across all of its versions. The version is the commit of
the rule's repository, so every commit to it starts a new version of every rule in it; the per-uuid
ceiling is what keeps that churn from growing storage.

Every match is counted in yara_qa_signatures.match_count, including the ones past the cap.

Concurrency. The recorders of several nodes can record the same rule at once, and none of them
should wait on a lock, so every step is a single statement or a short transaction:
- the slot is reserved by one conditional UPDATE of the (uuid, version) counter row. The
  per-version cap is exact. The per-uuid ceiling is read in the same statement, but two recorders
  storing under *different* versions of one uuid at the same instant can both pass it, so it can
  be exceeded by the number of versions racing (in practice, by one).
- the match row is inserted in the same transaction that reserves the slot, so a duplicate-key
  race (two recorders storing the same file under the same version) rolls the reservation back with
  it, and the loser renews the winner's row instead.
- the CAS puts run after that commit, outside any yara_qa transaction. If one fails, the row is
  deleted and the slot given back. A row whose match_digest is still NULL is one whose puts are in
  flight (or were interrupted), and readers skip it.

Every hold carries the same expiry as its row, so nothing is kept forever even if a prune or a
compensating delete never runs: GC collects an object once its holds have expired.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from saq.cas import Hold, get_cas
from saq.cas.errors import ObjectDeleting, ObjectNotFound, PoolNotFound
from saq.cas.pool import CASPool
from saq.configuration.config import get_config
from saq.database.model import YaraQAMatch, YaraQASignature
from saq.database.private_session import private_transaction
from saq.environment import get_global_runtime_settings
from saq.error.reporting import report_exception
from saq.json_encoding import _JSONEncoder
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.signatures.model import SIGNATURE_UUID_MAX_LENGTH
from saq.yara_scanning.match_record import serialize_match_record, summarize_match_record

if TYPE_CHECKING:
    # type hints only: importing saq.observables here would be circular at startup
    from saq.observables.file import FileObservable

# cas_holds.holder_kind for every yara_qa hold; the holder_id is the yara_qa_matches row id, which
# holds both the file and the match record
HOLDER_KIND = "yara_qa"

# column widths in yara_qa_matches / yara_qa_signatures
_RULE_NAME_MAX_LENGTH = 256
_NAMESPACE_MAX_LENGTH = 256
_FILE_NAME_MAX_LENGTH = 1024


class QARecordStatus(StrEnum):
    STORED = "stored"      # a new file was stored
    RENEWED = "renewed"    # the file was already stored for this version; its expiry was renewed
    CAPPED = "capped"      # counted, but not stored: a cap was reached
    SKIPPED = "skipped"    # not counted: no usable uuid, or no pool configured
    FAILED = "failed"      # something went wrong; logged


@dataclass(frozen=True)
class QATarget:
    """The file a QA rule matched, and where it came from."""
    path: str              # where the bytes can be read now (the yara service's spooled copy)
    sha256: str
    file_name: str
    file_size: int
    root_uuid: str
    observable_uuid: str

    def __str__(self) -> str:
        return f"{self.file_name} ({self.sha256})"

    @classmethod
    def from_file_observable(cls, file_observable: "FileObservable", root_uuid: str) -> "QATarget":
        return cls(path=file_observable.full_path, sha256=file_observable.sha256_hash,
                   file_name=file_observable.file_name, file_size=file_observable.size or 0,
                   root_uuid=root_uuid, observable_uuid=file_observable.uuid)


@dataclass(frozen=True)
class QARecordResult:
    status: QARecordStatus
    match_id: Optional[int] = None


def qa_hold(match_id: int, expires_at: datetime) -> Hold:
    return Hold(HOLDER_KIND, str(match_id), expires_at)


def _truncate(value: Optional[str], length: int) -> Optional[str]:
    return None if value is None else value[:length]


def _local_node() -> str:
    return get_global_runtime_settings().saq_node


#
# the counter row
#

def _count_match(session: Session, signature_uuid: str, signature_version: str, rule_name: str,
                 namespace: Optional[str], now: datetime) -> None:
    stmt = mysql_insert(YaraQASignature).values(
        signature_uuid=signature_uuid, signature_version=signature_version,
        rule_name=rule_name, namespace=namespace, match_count=1, stored_count=0,
        first_match_at=now, last_match_at=now)
    session.execute(stmt.on_duplicate_key_update(
        match_count=YaraQASignature.__table__.c.match_count + 1,
        last_match_at=now, rule_name=rule_name, namespace=namespace))


# one statement, so no lock is held past it and nothing waits in between. The per-uuid SUM is read
# through a derived table: MySQL refuses a subquery on the table being updated (error 1093) unless
# it is materialized first, and an aggregate cannot be merged into the outer query, so it always is
_RESERVE_SLOT = text("""
    UPDATE yara_qa_signatures
    SET stored_count = stored_count + 1
    WHERE signature_uuid = :signature_uuid
      AND signature_version = :signature_version
      AND stored_count < :max_per_version
      AND (SELECT total FROM (
            SELECT COALESCE(SUM(stored_count), 0) AS total
            FROM yara_qa_signatures
            WHERE signature_uuid = :signature_uuid) AS signature_total) < :max_per_signature
""")


def _reserve_slot(session: Session, signature_uuid: str, signature_version: str) -> bool:
    config = get_config().yara_qa
    result = session.execute(_RESERVE_SLOT, {
        "signature_uuid": signature_uuid,
        "signature_version": signature_version,
        "max_per_version": config.max_files_per_version,
        "max_per_signature": config.max_files_per_signature,
    })
    return result.rowcount == 1


#
# removing matches (shared with prune)
#

@dataclass(frozen=True)
class MatchRef:
    """What removing a match needs to know about it."""
    id: int
    signature_uuid: str
    signature_version: str
    sha256: str
    match_digest: Optional[str]
    expires_at: datetime

    @classmethod
    def from_row(cls, row) -> "MatchRef":
        return cls(row.id, row.signature_uuid, row.signature_version, row.sha256, row.match_digest, row.expires_at)


def delete_match_rows(session: Session, matches: list[MatchRef]) -> None:
    """Delete the rows (by primary key) and give their slots back, in the caller's transaction."""
    if not matches:
        return

    session.execute(
        delete(YaraQAMatch).where(YaraQAMatch.id.in_([m.id for m in matches]))
        .execution_options(synchronize_session=False))

    released: dict[tuple[str, str], int] = {}
    for match in matches:
        key = (match.signature_uuid, match.signature_version)
        released[key] = released.get(key, 0) + 1

    for (signature_uuid, signature_version), count in sorted(released.items()):
        session.execute(
            update(YaraQASignature)
            .where(YaraQASignature.signature_uuid == signature_uuid,
                   YaraQASignature.signature_version == signature_version)
            .values(stored_count=func.greatest(YaraQASignature.stored_count - count, 0))
            .execution_options(synchronize_session=False))


def release_match_holds(pool: CASPool, match: MatchRef) -> bool:
    """Release the match's holds on its file and its record. Returns False if a release failed
    (logged); the hold then simply expires, since it carries the match's expiry."""
    ok = True
    hold = qa_hold(match.id, match.expires_at)
    for digest in (match.sha256, match.match_digest):
        if digest is None:
            continue

        try:
            pool.release(digest, hold)
        except ObjectNotFound:
            pass
        except Exception as e:
            ok = False
            logging.warning("unable to release yara qa hold on %s for match %s: %s", digest, match.id, e)

    return ok


#
# record_qa_match
#

def record_qa_match(match_result: dict, target: QATarget) -> QARecordResult:
    """Count one QA-mode match and store the file and its match record if the caps allow.

    Never raises: a failure is logged and reported, and the match is not stored."""
    try:
        return record_qa_match_or_raise(match_result, target)
    except Exception as e:
        logging.error("unable to store yara qa match of rule %s on %s: %s", match_result.get("rule"), target, e)
        report_exception()
        return QARecordResult(QARecordStatus.FAILED)


def record_qa_match_or_raise(match_result: dict, target: QATarget) -> QARecordResult:
    """record_qa_match, raising whatever went wrong instead of reporting it, so the caller can tell
    a database that is unreachable for now from a match that cannot be stored."""
    config = get_config().yara_qa
    rule_name = _truncate(str(match_result.get("rule") or "unnamed"), _RULE_NAME_MAX_LENGTH)

    signature_uuid = str((match_result.get("meta") or {}).get("uuid") or "").strip()
    if not signature_uuid:
        # the detection path would attribute it to the built-in fallback uuid, which would pool the
        # samples of every uuid-less rule together, so they are not kept at all
        logging.warning("yara rule %s is in qa mode but has no uuid meta - its matches are not stored", rule_name)
        return QARecordResult(QARecordStatus.SKIPPED)

    if len(signature_uuid) > SIGNATURE_UUID_MAX_LENGTH:
        logging.warning("yara rule %s has a uuid longer than %s characters - its qa matches are not stored",
                        rule_name, SIGNATURE_UUID_MAX_LENGTH)
        return QARecordResult(QARecordStatus.SKIPPED)

    try:
        pool = get_cas().pool(config.pool)
    except PoolNotFound:
        logging.warning("cas pool %s is not configured - yara qa matches are not stored", config.pool)
        return QARecordResult(QARecordStatus.SKIPPED)

    signature_version = match_result.get("commit") or SIGNATURE_VERSION_UNKNOWN
    namespace = _truncate(match_result.get("namespace"), _NAMESPACE_MAX_LENGTH)
    sha256 = target.sha256
    file_path = target.path

    # naive local time, like every CAS hold expiry (compared against the database's NOW())
    now = datetime.now()
    expires_at = now + timedelta(days=config.retention_days)

    # committed on its own, so the match is counted whatever happens to the storage below
    with private_transaction() as session:
        _count_match(session, signature_uuid, signature_version, rule_name, namespace, now)

    renewed = _renew(pool, signature_uuid, signature_version, sha256, file_path, match_result, now, expires_at)
    if renewed is not None:
        return renewed

    summary = json.dumps(summarize_match_record(match_result), cls=_JSONEncoder)
    try:
        with private_transaction() as session:
            if not _reserve_slot(session, signature_uuid, signature_version):
                logging.debug("yara qa file cap reached for rule %s (%s @ %s)", rule_name, signature_uuid, signature_version)
                return QARecordResult(QARecordStatus.CAPPED)

            match = YaraQAMatch(
                signature_uuid=signature_uuid, signature_version=signature_version, sha256=sha256,
                file_name=_truncate(target.file_name, _FILE_NAME_MAX_LENGTH),
                file_size=target.file_size, root_uuid=target.root_uuid,
                observable_uuid=target.observable_uuid, node=_local_node(), match_digest=None,
                match_summary=summary, hit_count=1, first_seen=now, last_seen=now, expires_at=expires_at)
            session.add(match)
            session.flush()
            match_ref = MatchRef.from_row(match)
    except IntegrityError:
        # another recorder stored this file for this version first. the rollback gave the slot back
        renewed = _renew(pool, signature_uuid, signature_version, sha256, file_path, match_result, now, expires_at)
        return renewed if renewed is not None else QARecordResult(QARecordStatus.FAILED)

    hold = qa_hold(match_ref.id, expires_at)
    try:
        pool.put(file_path, hold=hold, digest=sha256)
        match_digest = pool.put(serialize_match_record(match_result), hold=hold)
    except Exception:
        release_match_holds(pool, match_ref)
        with private_transaction() as session:
            delete_match_rows(session, [match_ref])

        raise

    with private_transaction() as session:
        session.execute(
            update(YaraQAMatch).where(YaraQAMatch.id == match_ref.id).values(match_digest=match_digest)
            .execution_options(synchronize_session=False))

    logging.info("stored yara qa match %s: rule %s (%s @ %s) on %s", match_ref.id, rule_name, signature_uuid,
                 signature_version, target)
    return QARecordResult(QARecordStatus.STORED, match_ref.id)


def _renew(pool: CASPool, signature_uuid: str, signature_version: str, sha256: str, file_path: str,
           match_result: dict, now: datetime, expires_at: datetime) -> Optional[QARecordResult]:
    """If this file is already stored for this version, count the hit and renew its expiry and
    holds. Returns None when there is no such row."""
    with private_transaction() as session:
        result = session.execute(
            update(YaraQAMatch)
            .where(YaraQAMatch.signature_uuid == signature_uuid,
                   YaraQAMatch.signature_version == signature_version,
                   YaraQAMatch.sha256 == sha256)
            .values(hit_count=YaraQAMatch.hit_count + 1, last_seen=now, expires_at=expires_at)
            .execution_options(synchronize_session=False))
        if result.rowcount != 1:
            return None

        match_id, match_digest = session.execute(
            select(YaraQAMatch.id, YaraQAMatch.match_digest)
            .where(YaraQAMatch.signature_uuid == signature_uuid,
                   YaraQAMatch.signature_version == signature_version,
                   YaraQAMatch.sha256 == sha256)).one()

    hold = qa_hold(match_id, expires_at)
    _renew_hold(pool, sha256, hold, lambda: pool.put(file_path, hold=hold, digest=sha256))

    # a NULL digest means another recorder's puts are in flight; it sets the digest when they finish
    if match_digest is not None:
        def _restore_record():
            # the object is gone (its hold lapsed before this match came in): store this match's
            # record in its place
            new_digest = pool.put(serialize_match_record(match_result), hold=hold)
            with private_transaction() as session:
                session.execute(
                    update(YaraQAMatch).where(YaraQAMatch.id == match_id)
                    .values(match_digest=new_digest,
                            match_summary=json.dumps(summarize_match_record(match_result), cls=_JSONEncoder))
                    .execution_options(synchronize_session=False))

        _renew_hold(pool, match_digest, hold, _restore_record)

    return QARecordResult(QARecordStatus.RENEWED, match_id)


def _renew_hold(pool: CASPool, digest: str, hold: Hold, restore) -> None:
    try:
        pool.hold(digest, hold)
    except (ObjectNotFound, ObjectDeleting):
        restore()

