"""The YARA validation queue (saq.svs.validations): requests, the cache, the lease and retention."""

import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import delete, func, select, update

from saq.configuration.config import get_config
from saq.database.model import Alert, SVSValidation, SVSValidationResult, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.svs import actions, validations
from saq.svs.constants import ValidationState
from saq.svs.validations import (
    LeaseLost,
    claim,
    complete,
    corpus_version,
    engine_fingerprint,
    fail,
    fail_abandoned,
    heartbeat,
    prune,
    release,
    request_validation,
)
from saq.svs.yara.diff import Category, Outcome, ResultRow
from saq.svs.yara.replay import FileError, ReplayResult, SideReport
from tests.saq.svs.conftest import RULE_UUID, graded_alert, set_disposition
from tests.saq.svs.yara.conftest import REPOSITORY, stored_sample

pytestmark = pytest.mark.integration

BASE = "a" * 40
HEAD = "b" * 40
LEASE = {"lease_seconds": 300, "max_attempts": 3}


def _user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _request(base: str = BASE, head: str = HEAD) -> tuple[str, bool]:
    return request_validation(REPOSITORY, base, head, "feature", "https://git.example/pr/1", _user_id())


def _row(validation_uuid: str) -> SVSValidation:
    get_db().commit()
    get_db().expire_all()
    return get_db().execute(select(SVSValidation).where(SVSValidation.uuid == validation_uuid)).scalar_one()


def _result(rows: list[ResultRow] = (), *, file_errors: list[FileError] = ()) -> ReplayResult:
    """A replay result as run_replay returns it."""
    counts = {category.value: 0 for category in Category}
    for row in rows:
        counts[row.category.value] += 1

    return ReplayResult(
        repository=REPOSITORY, base_sha=BASE, head_sha=HEAD,
        base=SideReport(sha=BASE), head=SideReport(sha=HEAD, file_errors=list(file_errors)),
        diffed=True, rows=list(rows), counts=counts)


def _result_row(category: Category, sha256: str = "ab" * 32) -> ResultRow:
    return ResultRow(sha256=sha256, rule_uuid=RULE_UUID, rule_name="svs_rule", namespace="acme", label="tp",
                     label_source="inherited_single", base=Outcome.MATCH, head=Outcome.MISS, raw_base=True,
                     raw_head=False, category=category)


def _complete(validation_uuid: str, rows: list[ResultRow] = ()) -> None:
    claimed = claim("node1", **LEASE)
    assert claimed.uuid == validation_uuid
    complete(claimed, _result(rows), corpus_version_=corpus_version(), engine_fingerprint_=engine_fingerprint(REPOSITORY))


def _expire_lease(validation_uuid: str) -> None:
    with private_transaction() as session:
        session.execute(update(SVSValidation).where(SVSValidation.uuid == validation_uuid)
                        .values(heartbeat_at=datetime.now() - timedelta(hours=1)))


#
# requests and the cache
#

def test_an_identical_request_shares_the_queued_validation(svs_repository):
    validation_uuid, created = _request()
    assert created
    row = _row(validation_uuid)
    assert (row.state, row.repository, row.branch, row.requested_by) == ("queued", REPOSITORY, "feature", _user_id())

    assert _request() == (validation_uuid, False)
    assert _request(head="c" * 40)[1]


def test_a_completed_validation_answers_until_the_corpus_changes(svs_repository):
    validation_uuid, _ = _request()
    _complete(validation_uuid)
    assert _row(validation_uuid).active_key is None

    assert _request() == (validation_uuid, False)

    # a new sample changes the corpus: the next request runs again
    graded_alert("DELIVERY", {"new.bin": [RULE_UUID]})
    again, created = _request()
    assert created and again != validation_uuid


def test_a_failed_validation_is_never_reused(svs_repository):
    validation_uuid, _ = _request()
    fail(claim("node1", **LEASE), "the scan failed")
    assert _row(validation_uuid).state == "failed"

    again, created = _request()
    assert created and again != validation_uuid


def test_concurrent_identical_requests_share_one_validation(svs_repository):
    first, _ = _request()
    # the second request read nothing before the first one inserted its row
    with patch.object(validations, "_active_uuid", side_effect=[None, first]):
        assert _request() == (first, False)

    assert get_db().execute(select(func.count()).select_from(SVSValidation)).scalar_one() == 1


def test_the_corpus_version_follows_every_input(svs_repository):
    alert, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    sha256 = files["a.bin"].value.lower()
    versions = [corpus_version()]

    def _changed():
        versions.append(corpus_version())
        assert versions[-1] != versions[-2]

    actions.relabel(sha256, RULE_UUID, "fp", _user_id())
    _changed()
    # clearing a verdict bumps no change time; the history count catches it
    actions.reset_label(sha256, RULE_UUID, _user_id())
    _changed()
    actions.retire(sha256, RULE_UUID, _user_id(), "intended")
    _changed()
    set_disposition(alert.uuid, "FALSE_POSITIVE")
    _changed()
    get_db().execute(delete(Alert).where(Alert.id == alert.id))
    get_db().commit()
    _changed()
    assert corpus_version() == versions[-1]


def test_the_engine_fingerprint_follows_the_disposition_classification(svs_repository, monkeypatch):
    fingerprint = engine_fingerprint(REPOSITORY)
    assert engine_fingerprint(REPOSITORY) == fingerprint

    monkeypatch.setitem(get_config().disposition_classification, "REVIEWED", "fp")
    assert engine_fingerprint(REPOSITORY) != fingerprint


#
# the lease
#

def test_only_one_worker_claims_a_validation(svs_repository):
    validation_uuid, _ = _request()
    first = claim("node1", **LEASE)
    assert (first.uuid, first.attempts) == (validation_uuid, 1)
    assert claim("node2", **LEASE) is None

    row = _row(validation_uuid)
    assert (row.state, row.claimed_by, row.claim_token) == ("running", "node1", first.token)
    assert heartbeat(first)


def test_an_expired_lease_is_taken_over(svs_repository):
    validation_uuid, _ = _request()
    first = claim("node1", **LEASE)
    _expire_lease(validation_uuid)

    second = claim("node2", **LEASE)
    assert (second.uuid, second.attempts) == (validation_uuid, 2)
    # the first worker's work is void
    assert not heartbeat(first)
    with pytest.raises(LeaseLost):
        complete(first, _result([_result_row(Category.REGRESSION)]), corpus_version_="v", engine_fingerprint_="f")
    assert get_db().execute(select(func.count()).select_from(SVSValidationResult)).scalar_one() == 0
    assert not fail(first, "late")
    assert _row(validation_uuid).state == "running"


def test_a_validation_abandoned_too_often_fails(svs_repository):
    validation_uuid, _ = _request()
    for _ in range(3):
        assert claim("node1", **LEASE) is not None
        _expire_lease(validation_uuid)

    assert claim("node1", **LEASE) is None
    assert fail_abandoned(**LEASE) == 1
    row = _row(validation_uuid)
    assert (row.state, row.active_key) == ("failed", None)
    assert "stopped 3 times" in row.error


def test_a_released_validation_returns_to_the_queue(svs_repository):
    validation_uuid, _ = _request()
    claimed = claim("node1", **LEASE)
    assert release(claimed)

    row = _row(validation_uuid)
    assert (row.state, row.attempts, row.claim_token, row.claimed_by) == ("queued", 0, None, None)
    assert row.active_key is not None
    assert claim("node2", **LEASE).uuid == validation_uuid


def test_complete_stores_the_report_and_its_rows(svs_repository):
    validation_uuid, _ = _request()
    claimed = claim("node1", **LEASE)
    result = _result([_result_row(Category.REGRESSION), _result_row(Category.NEW_FP_OTHER_RULE, "cd" * 32)],
                     file_errors=[FileError("yara/acme/broken.yar", "acme", "syntax error")])

    complete(claimed, result, corpus_version_="v" * 64, engine_fingerprint_="f" * 64)

    row = _row(validation_uuid)
    assert (row.state, row.claim_token, row.active_key, row.diffed) == ("completed", None, None, True)
    assert (row.regressions, row.new_fps, row.compile_errors) == (1, 1, 1)
    assert json.loads(row.counts)["regression"] == 1
    report = json.loads(row.report)
    assert "rows" not in report
    assert report["head"]["file_errors"][0]["file"] == "yara/acme/broken.yar"
    assert row.finished_at is not None
    results = get_db().execute(select(SVSValidationResult).order_by(SVSValidationResult.id)).scalars().all()
    assert [(r.sha256, r.category, r.base, r.head, r.label) for r in results] == [
        ("ab" * 32, "regression", "match", "miss", "tp"),
        ("cd" * 32, "new_fp_other_rule", "match", "miss", "tp"),
    ]


#
# retention and deletion
#

def test_prune_removes_old_finished_validations_with_their_results(svs_repository, monkeypatch):
    monkeypatch.setattr(get_config().svs.yara, "prune_batch_size", 1)
    old, _ = _request()
    _complete(old, [_result_row(Category.REGRESSION)])
    recent, _ = _request(head="c" * 40)
    _complete(recent)
    queued, _ = _request(head="d" * 40)
    with private_transaction() as session:
        session.execute(update(SVSValidation).where(SVSValidation.uuid.in_([old, queued]))
                        .values(finished_at=datetime.now() - timedelta(days=200),
                                created_at=datetime.now() - timedelta(days=200)))

    assert prune(dry_run=True) == 1
    assert prune() == 1
    remaining = set(get_db().execute(select(SVSValidation.uuid)).scalars())
    assert remaining == {recent, queued}
    assert get_db().execute(select(func.count()).select_from(SVSValidationResult)).scalar_one() == 0


def test_deleting_a_sample_removes_it_from_every_report(svs_repository):
    sha256 = stored_sample("DELIVERY", b"svs validation delete", [RULE_UUID])
    validation_uuid, _ = _request()
    _complete(validation_uuid, [_result_row(Category.REGRESSION, sha256), _result_row(Category.REGRESSION)])

    actions.delete_sample(sha256, _user_id(), "privacy request", actor="unittest")

    remaining = get_db().execute(select(SVSValidationResult.sha256)).scalars().all()
    assert remaining == ["ab" * 32]
