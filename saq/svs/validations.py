"""The YARA validation queue (docs/SVS_VALIDATION.md, *The svs service*).

A validation is requested through the API (request_validation), waits in svs_validations as
queued, and is run by a service_svs worker that holds a lease on it:

- claim() takes the oldest queued validation, or a running one whose worker stopped heartbeating,
  with one conditional UPDATE that repeats the condition, so two workers never both win;
- heartbeat() keeps the lease; a worker that loses it (another one took over) stops;
- complete() stores the report and its rows, fail() the reason it could not run, release() puts it
  back in the queue when the service stops;
- fail_abandoned() gives up on a validation the service stopped too many times while running.

Lease times come from the database clock, never the worker's. A completed validation answers a
later request for the same commits while the corpus version (what the samples and their labels
are) and the engine fingerprint (what decides the results) are unchanged. Only this module writes
svs_validations and svs_validation_results.
"""

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import yara
import yara_scanner
from sqlalchemy import and_, delete, func, insert, or_, select, text, update
from sqlalchemy.exc import IntegrityError

from saq.configuration.config import get_config, get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.database.model import (
    Alert,
    DetectionPointVerdictHistory,
    SVSSampleDeletion,
    SVSSampleRetirement,
    SVSValidation,
    SVSValidationResult,
    SVSYaraCapture,
)
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs.constants import CaptureState, ValidationState
from saq.svs.yara import child
from saq.svs.yara.diff import Category
from saq.svs.yara.layout import resolve_layout

if TYPE_CHECKING:
    # replay imports the signature loaders, which the API must not import while saq loads
    from saq.svs.yara.replay import ReplayResult

FINISHED_STATES = (ValidationState.COMPLETED, ValidationState.FAILED)

# the categories each filterable count adds up
REGRESSION_CATEGORIES = (Category.REGRESSION, Category.REGRESSION_UNCONFIRMED)
NEW_FP_CATEGORIES = (Category.NEW_FP, Category.NEW_FP_OTHER_RULE)

# result rows inserted per statement
_RESULT_BATCH = 1000

# the sources whose code decides a validation's results
_ENGINE_SOURCES = Path(child.__file__).parent


class LeaseLost(Exception):
    """Another worker owns the validation now: this one's work on it is void."""


@dataclass(frozen=True)
class Claim:
    """A validation a worker holds the lease on."""
    id: int
    uuid: str
    repository: str
    base_sha: str
    head_sha: str
    branch: str
    token: str
    attempts: int


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def active_key(repository: str, base_sha: str, head_sha: str) -> str:
    return _digest([repository, base_sha, head_sha])


#
# what a result depends on
#

def corpus_version() -> str:
    """A digest of what the corpus and its labels are: the greatest change time and the number of
    rows of every input, read in one transaction. The counts catch what bumps no change time: a
    cleared verdict, a deleted alert, a deleted capture."""
    stored = SVSYaraCapture.state == CaptureState.STORED
    alert_uuids = select(SVSYaraCapture.alert_uuid).where(stored).distinct()
    statements = {
        "captures": select(func.max(SVSYaraCapture.updated_at), func.count()).where(stored),
        "verdicts": select(func.max(DetectionPointVerdictHistory.changed_at), func.count()),
        "retirements": select(func.max(SVSSampleRetirement.updated_at), func.count()),
        "deletions": select(func.max(SVSSampleDeletion.updated_at), func.count()),
        "alerts": select(func.max(Alert.updated_at), func.count()).where(Alert.uuid.in_(alert_uuids)),
    }
    with private_transaction() as session:
        inputs = {name: [str(value) for value in session.execute(statement).one()]
                  for name, statement in statements.items()}

    return _digest(inputs)


def _engine_sources_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted(_ENGINE_SOURCES.glob("*.py")):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())

    return digest.hexdigest()


def engine_fingerprint(repository: str) -> str:
    """A digest of what decides a validation's results besides the corpus and the commits: the
    replay's code and protocol, the YARA libraries, how dispositions classify, the per-file scan
    timeout and which directories of the repository are loaded. Raises LayoutError."""
    return _digest({
        "protocol": child.PROTOCOL_VERSION,
        "yara_python": yara.__version__,
        "yara_scanner": yara_scanner.__version__,
        "sources": _engine_sources_digest(),
        "disposition_classification": dict(get_config().disposition_classification),
        "file_timeout": get_service_config(SERVICE_YARA_SCANNER).default_timeout,
        "layout": asdict(resolve_layout(repository)),
    })


#
# requests
#

def get_validation(validation_uuid: str) -> Optional[SVSValidation]:
    return get_db().execute(select(SVSValidation).where(SVSValidation.uuid == validation_uuid)).scalar_one_or_none()


def _active_uuid(key: str) -> Optional[str]:
    get_db().commit()
    return get_db().execute(select(SVSValidation.uuid).where(SVSValidation.active_key == key)).scalar_one_or_none()


def _cached_uuid(repository: str, base_sha: str, head_sha: str) -> Optional[str]:
    version, fingerprint = corpus_version(), engine_fingerprint(repository)
    return get_db().execute(
        select(SVSValidation.uuid)
        .where(SVSValidation.repository == repository,
               SVSValidation.base_sha == base_sha,
               SVSValidation.head_sha == head_sha,
               SVSValidation.state == ValidationState.COMPLETED,
               SVSValidation.corpus_version == version,
               SVSValidation.engine_fingerprint == fingerprint)
        .order_by(SVSValidation.finished_at.desc(), SVSValidation.id.desc())
        .limit(1)).scalar_one_or_none()


def request_validation(repository: str, base_sha: str, head_sha: str, branch: str, pr_url: Optional[str],
                       user_id: Optional[int]) -> tuple[str, bool]:
    """The validation that answers this request, and whether it is new: one queued or running for
    the same commits, else a completed one whose corpus version and engine fingerprint are still
    current, else a new queued one. A failed validation is never reused. Returns (uuid, created).
    Raises LayoutError for a repository that cannot be validated."""
    key = active_key(repository, base_sha, head_sha)
    for _ in range(3):
        existing = _active_uuid(key) or _cached_uuid(repository, base_sha, head_sha)
        get_db().commit()
        if existing is not None:
            return existing, False

        validation_uuid = str(uuid.uuid4())
        try:
            with private_transaction() as session:
                session.add(SVSValidation(
                    uuid=validation_uuid, repository=repository, base_sha=base_sha, head_sha=head_sha,
                    branch=branch, pr_url=pr_url, requested_by=user_id, created_at=datetime.now(),
                    state=ValidationState.QUEUED, active_key=key, attempts=0))
        except IntegrityError:
            # an identical request inserted its validation first; the next pass returns it
            continue

        return validation_uuid, True

    raise RuntimeError(f"unable to request a validation of {repository} {base_sha}..{head_sha}")


#
# the lease
#

def _expired(lease_seconds: int):
    return SVSValidation.heartbeat_at < func.date_sub(func.now(6), text(f"INTERVAL {int(lease_seconds)} SECOND"))


def _claimable(lease_seconds: int, max_attempts: int):
    return or_(
        SVSValidation.state == ValidationState.QUEUED,
        and_(SVSValidation.state == ValidationState.RUNNING, _expired(lease_seconds), SVSValidation.attempts < max_attempts))


def claim(node: str, *, lease_seconds: int, max_attempts: int, candidates: int = 10) -> Optional[Claim]:
    """Takes the lease on the oldest validation that is queued, or running under an expired lease
    with attempts left. None when there is nothing to run."""
    with private_transaction() as session:
        ids = session.execute(
            select(SVSValidation.id)
            .where(_claimable(lease_seconds, max_attempts))
            .order_by(SVSValidation.created_at, SVSValidation.id)
            .limit(candidates)).scalars().all()

    for validation_id in ids:
        token = str(uuid.uuid4())
        with private_transaction() as session:
            # the condition is repeated: another worker may have claimed it since it was read
            claimed = session.execute(
                update(SVSValidation)
                .where(SVSValidation.id == validation_id, _claimable(lease_seconds, max_attempts))
                .values(state=ValidationState.RUNNING, claim_token=token, claimed_by=node, heartbeat_at=func.now(6),
                        attempts=SVSValidation.attempts + 1, started_at=func.now(), error=None)
                .execution_options(synchronize_session=False)).rowcount
            if claimed != 1:
                continue

            row = session.execute(select(SVSValidation).where(SVSValidation.id == validation_id)).scalar_one()
            return Claim(row.id, row.uuid, row.repository, row.base_sha, row.head_sha, row.branch, token, row.attempts)

    return None


def _owned(claim_: Claim):
    return and_(SVSValidation.id == claim_.id, SVSValidation.claim_token == claim_.token,
                SVSValidation.state == ValidationState.RUNNING)


def heartbeat(claim_: Claim) -> bool:
    """Extends the lease. False when the worker no longer holds it."""
    with private_transaction() as session:
        return session.execute(
            update(SVSValidation).where(_owned(claim_)).values(heartbeat_at=func.now(6))
            .execution_options(synchronize_session=False)).rowcount == 1


def release(claim_: Claim) -> bool:
    """Puts a validation the stopping service was running back in the queue, without counting the
    attempt: a shutdown is not the validation's fault."""
    with private_transaction() as session:
        return session.execute(
            update(SVSValidation).where(_owned(claim_))
            .values(state=ValidationState.QUEUED, claim_token=None, claimed_by=None, heartbeat_at=None, started_at=None,
                    attempts=func.greatest(SVSValidation.attempts - 1, 0))
            .execution_options(synchronize_session=False)).rowcount == 1


def _finish(**values) -> dict:
    return {"claim_token": None, "active_key": None, "finished_at": func.now(), **values}


def fail(claim_: Claim, message: str) -> bool:
    """Records that the validation could not run, and why. False when the worker no longer held it."""
    with private_transaction() as session:
        return session.execute(
            update(SVSValidation).where(_owned(claim_)).values(**_finish(state=ValidationState.FAILED, error=message))
            .execution_options(synchronize_session=False)).rowcount == 1


def fail_abandoned(*, lease_seconds: int, max_attempts: int) -> int:
    """Fails the running validations whose lease expired after max_attempts claims: the service
    stopped (or died) every time it ran them. Returns how many."""
    with private_transaction() as session:
        count = session.execute(
            update(SVSValidation)
            .where(SVSValidation.state == ValidationState.RUNNING, _expired(lease_seconds),
                   SVSValidation.attempts >= max_attempts)
            .values(**_finish(state=ValidationState.FAILED,
                              error=f"the svs service stopped {max_attempts} times while running it"))
            .execution_options(synchronize_session=False)).rowcount

    if count:
        logging.warning("failed %d abandoned svs validations", count)
    return count


def _count(counts: dict[str, int], categories) -> int:
    return sum(counts.get(category.value, 0) for category in categories)


def complete(claim_: Claim, result: "ReplayResult", *, corpus_version_: str, engine_fingerprint_: str) -> None:
    """Stores the report and its rows and marks the validation completed, in one transaction.
    Raises LeaseLost, storing nothing, when the worker no longer holds the lease."""
    report = result.to_dict()
    report.pop("rows")
    counts = dict(result.counts)
    compile_errors = len(result.head.file_errors) + (0 if result.head.loads else 1)
    with private_transaction() as session:
        updated = session.execute(
            update(SVSValidation).where(_owned(claim_))
            .values(**_finish(
                state=ValidationState.COMPLETED,
                corpus_version=corpus_version_, engine_fingerprint=engine_fingerprint_,
                counts=json.dumps(counts), report=json.dumps(report, default=str),
                regressions=_count(counts, REGRESSION_CATEGORIES), new_fps=_count(counts, NEW_FP_CATEGORIES),
                compile_errors=compile_errors, diffed=result.diffed))
            .execution_options(synchronize_session=False)).rowcount
        if updated != 1:
            raise LeaseLost(f"validation {claim_.uuid} is no longer held by this worker")

        rows = [{
            "validation_id": claim_.id, "sha256": row.sha256, "rule_uuid": row.rule_uuid,
            "rule_name": row.rule_name, "namespace": row.namespace, "label": row.label,
            "label_source": row.label_source, "base": row.base.value, "head": row.head.value,
            "raw_base": row.raw_base, "raw_head": row.raw_head, "category": row.category.value,
            "note": row.note,
        } for row in result.rows]
        for start in range(0, len(rows), _RESULT_BATCH):
            session.execute(insert(SVSValidationResult), rows[start:start + _RESULT_BATCH])


#
# retention
#

def prune(*, dry_run: bool = False) -> int:
    """Deletes the finished validations older than svs.yara.retention_days, with their results, in
    batches. Returns how many were (or, with dry_run, would be) deleted."""
    config = get_config().svs.yara
    cutoff = datetime.now() - timedelta(days=config.retention_days)
    expired = and_(SVSValidation.state.in_(FINISHED_STATES), SVSValidation.finished_at < cutoff)
    if dry_run:
        with private_transaction() as session:
            return session.execute(select(func.count()).select_from(SVSValidation).where(expired)).scalar_one()

    total = 0
    while True:
        with private_transaction() as session:
            ids = session.execute(
                select(SVSValidation.id).where(expired).order_by(SVSValidation.id)
                .limit(config.prune_batch_size).with_for_update(skip_locked=True)).scalars().all()
            if ids:
                # the results go with them (ON DELETE CASCADE)
                session.execute(delete(SVSValidation).where(SVSValidation.id.in_(ids))
                                .execution_options(synchronize_session=False))

        total += len(ids)
        if len(ids) < config.prune_batch_size:
            break

    if total:
        logging.info("pruned %d svs validations finished before %s", total, cutoff)
    return total
