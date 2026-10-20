"""The analyst actions on SVS samples (saq.svs.actions): relabel, reset, confirm, retire and delete."""

import json
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import delete, select, update

from saq.cas import Hold, get_cas
from saq.cas.errors import LegalHoldActive
from saq.cas.pool import CASPool
from saq.configuration.config import get_config
from saq.database.model import Alert, CASPurge, SVSSampleDeletion, SVSSampleRetirement, SVSYaraCapture, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.detection_verdicts.constants import SOURCE_EXPLICIT, SOURCE_INHERITED_MULTI, SOURCE_INHERITED_SINGLE
from saq.detection_verdicts.store import VerdictNotAllowed
from saq.svs import actions, capture as capture_module
from saq.svs.actions import NotRetired, SampleNotFound, WrongNode
from saq.svs.capture import CaptureStatus, candidates_from_root, capture
from saq.svs.samples import changed_since_condition, get_sample, samples_subquery
from saq.svs.storage import capture_hold
from tests.saq.svs.conftest import (
    OTHER_RULE_UUID,
    RULE_UUID,
    add_file,
    add_yara_match,
    capture_rows,
    graded_alert,
    insert_capture,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _sample(sha256: str, rule_uuid: str = RULE_UUID) -> dict:
    get_db().expire_all()
    return get_sample(sha256, rule_uuid)


def _label(sha256: str, rule_uuid: str = RULE_UUID) -> tuple:
    sample = _sample(sha256, rule_uuid)
    return sample["label"], sample["label_source"]


def _sha256(files: dict, name: str = "a.bin") -> str:
    return files[name].value.lower()


#
# relabel, reset, confirm
#

def test_relabel_writes_an_explicit_verdict_on_every_contributing_detection(user_id):
    content = b"svs relabel sample"
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]}, contents={"a.bin": content})
    graded_alert("DELIVERY", {"a.bin": [RULE_UUID]}, contents={"a.bin": content})
    sha256 = _sha256(files)
    assert _label(sha256) == ("tp", SOURCE_INHERITED_SINGLE)

    change = actions.relabel(sha256, RULE_UUID, "fp", user_id)

    assert (change.changed, change.unchanged, change.skipped) == (2, 0, [])
    assert (change.label, change.label_source) == ("fp", SOURCE_EXPLICIT)
    assert _sample(sha256)["votes"]["fp_explicit"] == 2
    # the other rule's sample of the same file is untouched
    assert _label(sha256, OTHER_RULE_UUID) == ("tp", SOURCE_INHERITED_MULTI)

    # again: nothing to change
    change = actions.relabel(sha256, RULE_UUID, "fp", user_id)
    assert (change.changed, change.unchanged) == (0, 2)


def test_relabel_skips_the_detections_on_a_false_positive_alert(user_id):
    content = b"svs relabel across classes"
    fp_alert, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID]}, contents={"a.bin": content})
    graded_alert("DELIVERY", {"a.bin": [RULE_UUID]}, contents={"a.bin": content})
    sha256 = _sha256(files)
    assert _label(sha256) == ("conflicted", SOURCE_INHERITED_SINGLE)

    change = actions.relabel(sha256, RULE_UUID, "tp", user_id)

    assert change.changed == 1
    (skipped,) = change.skipped
    assert skipped.alert_uuid == fp_alert.uuid
    assert "correct its disposition" in skipped.reason
    # the explicit vote outweighs the FP alert's inherited one
    assert (change.label, change.label_source) == ("tp", SOURCE_EXPLICIT)


def test_relabel_with_nothing_writable_is_refused(user_id):
    _, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID]})
    with pytest.raises(VerdictNotAllowed, match="correct its disposition"):
        actions.relabel(_sha256(files), RULE_UUID, "tp", user_id)
    assert _label(_sha256(files)) == ("fp", SOURCE_INHERITED_SINGLE)


def test_relabel_skips_alerts_whose_disposition_only_ace_sets(user_id):
    _, files = graded_alert("SIMULATED", {"a.bin": [RULE_UUID]})
    with pytest.raises(VerdictNotAllowed, match="set by ACE"):
        actions.relabel(_sha256(files), RULE_UUID, "fp", user_id)


def test_relabel_of_a_sample_whose_alerts_are_gone_is_refused(user_id):
    alert, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    get_db().execute(delete(Alert).where(Alert.id == alert.id))
    get_db().commit()
    with pytest.raises(VerdictNotAllowed, match="deleted"):
        actions.relabel(_sha256(files), RULE_UUID, "fp", user_id)


def test_an_unknown_sample(user_id):
    with pytest.raises(SampleNotFound):
        actions.relabel("ab" * 32, RULE_UUID, "fp", user_id)
    with pytest.raises(SampleNotFound):
        actions.confirm("ab" * 32, RULE_UUID, user_id)


def test_reset_clears_the_explicit_verdicts(user_id):
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    sha256 = _sha256(files)
    actions.relabel(sha256, RULE_UUID, "fp", user_id)

    change = actions.reset_label(sha256, RULE_UUID, user_id)

    assert change.changed == 1
    assert (change.label, change.label_source) == ("tp", SOURCE_INHERITED_SINGLE)

    # again: nothing to reset, which is not an error
    change = actions.reset_label(sha256, RULE_UUID, user_id)
    assert (change.changed, change.unchanged, change.skipped) == (0, 0, [])


def test_reset_leaves_out_the_detections_on_a_false_positive_alert(user_id):
    content = b"svs reset across classes"
    _, files = graded_alert("FALSE_POSITIVE", {"a.bin": [RULE_UUID]}, contents={"a.bin": content})
    graded_alert("DELIVERY", {"a.bin": [RULE_UUID]}, contents={"a.bin": content})
    sha256 = _sha256(files)
    actions.relabel(sha256, RULE_UUID, "tp", user_id)

    change = actions.reset_label(sha256, RULE_UUID, user_id)

    # the FP alert's detection had nothing to clear, so it is not listed as skipped
    assert (change.changed, change.skipped) == (1, [])
    assert (change.label, change.label_source) == ("conflicted", SOURCE_INHERITED_SINGLE)


def test_confirm_upgrades_only_the_unconfirmed_detections(user_id):
    content = b"svs confirm sample"
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]}, contents={"a.bin": content})
    sha256 = _sha256(files)
    assert _label(sha256) == ("tp", SOURCE_INHERITED_MULTI)

    change = actions.confirm(sha256, RULE_UUID, user_id)

    assert change.changed == 1
    assert (change.label, change.label_source) == ("tp", SOURCE_EXPLICIT)
    assert _label(sha256, OTHER_RULE_UUID) == ("tp", SOURCE_INHERITED_MULTI)
    # nothing left to confirm is not an error
    assert actions.confirm(sha256, RULE_UUID, user_id).changed == 0


def test_confirm_leaves_an_fp_override_alone(user_id):
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID, OTHER_RULE_UUID]})
    sha256 = _sha256(files)
    actions.relabel(sha256, RULE_UUID, "fp", user_id)
    assert actions.confirm(sha256, RULE_UUID, user_id).changed == 0
    assert _label(sha256) == ("fp", SOURCE_EXPLICIT)


#
# retire
#

def test_retire_and_unretire(user_id):
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    sha256 = _sha256(files)
    assert _sample(sha256)["retired"] is False

    row = actions.retire(sha256, RULE_UUID, user_id, "  the rule no longer targets this family  ")
    assert row.reason == "the rule no longer targets this family"
    sample = _sample(sha256)
    assert sample["retired"] is True
    assert sample["retired_by"] == "unittest"
    assert sample["retired_reason"] == "the rule no longer targets this family"
    assert actions.retired_pairs() == {(sha256, RULE_UUID)}

    # retiring a retired sample keeps the first reason
    actions.retire(sha256, RULE_UUID, user_id, "another reason")
    assert _sample(sha256)["retired_reason"] == "the rule no longer targets this family"

    row = actions.unretire(sha256, RULE_UUID, user_id)
    assert row.unretired_at is not None
    assert _sample(sha256)["retired"] is False
    assert actions.retired_pairs() == frozenset()
    with pytest.raises(NotRetired):
        actions.unretire(sha256, RULE_UUID, user_id)

    # the row is reused, so there is one per pair
    actions.retire(sha256, RULE_UUID, user_id, "retired again")
    assert _sample(sha256)["retired_reason"] == "retired again"
    rows = get_db().execute(select(SVSSampleRetirement)).scalars().all()
    assert len(rows) == 1 and rows[0].unretired_at is None


def test_retire_needs_a_reason_and_a_sample(user_id):
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    with pytest.raises(ValueError):
        actions.retire(_sha256(files), RULE_UUID, user_id, "   ")
    with pytest.raises(SampleNotFound):
        actions.retire(_sha256(files), OTHER_RULE_UUID, user_id, "no such sample")
    with pytest.raises(NotRetired):
        actions.unretire(_sha256(files), RULE_UUID, user_id)


def test_retirements_are_seen_by_changed_since(user_id):
    _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]})
    sha256 = _sha256(files)

    def changed(since: datetime) -> bool:
        samples = samples_subquery()
        get_db().commit()
        return get_db().execute(
            select(samples.c.sha256).where(samples.c.sha256 == sha256)
            .where(changed_since_condition(samples, since))).first() is not None

    # nothing else about the sample changed lately
    get_db().execute(update(SVSYaraCapture).values(updated_at=datetime(2020, 1, 1)))
    get_db().execute(update(Alert).values(updated_at=datetime(2020, 1, 1)))
    get_db().commit()
    since = datetime.now() - timedelta(minutes=1)
    assert not changed(since)

    actions.retire(sha256, RULE_UUID, user_id, "retired")
    assert changed(since)
    with private_transaction() as session:
        session.execute(update(SVSSampleRetirement).values(updated_at=datetime(2020, 1, 1)))
    assert not changed(since)
    actions.unretire(sha256, RULE_UUID, user_id)
    assert changed(since)


#
# delete
#

@pytest.fixture
def svs_pool() -> CASPool:
    return get_cas().pool(get_config().svs.samples.pool)


def _stored_sample(pool: CASPool, rule_uuids: list[str], content: bytes, record: bytes | None = None) -> str:
    """A file captured for each rule, its bytes and a match record per capture in the pool, held
    as capture holds them. Returns its sha256."""
    alert, files = graded_alert("DELIVERY", {"a.bin": rule_uuids}, contents={"a.bin": content})
    for row in capture_rows(alert.uuid):
        pool.put(content, hold=capture_hold(row.id), digest=row.sha256)
        digest = pool.put(record if record is not None else f"record {row.id}".encode(), hold=capture_hold(row.id))
        with private_transaction() as session:
            session.execute(update(SVSYaraCapture).where(SVSYaraCapture.id == row.id).values(record_digest=digest))

    return _sha256(files)


def _deletion(sha256: str):
    with private_transaction() as session:
        row = session.execute(select(SVSSampleDeletion).where(SVSSampleDeletion.sha256 == sha256)).scalar_one_or_none()
        if row is not None:
            session.expunge(row)
        return row


def _captures_of(sha256: str) -> list[SVSYaraCapture]:
    return [row for row in capture_rows() if row.sha256 == sha256]


def test_delete_removes_the_file_from_svs(user_id, svs_pool):
    sha256 = _stored_sample(svs_pool, [RULE_UUID, OTHER_RULE_UUID], b"svs delete sample")
    records = [row.record_digest for row in _captures_of(sha256)]
    actions.retire(sha256, RULE_UUID, user_id, "retired")
    other = _stored_sample(svs_pool, [RULE_UUID], b"another svs sample")

    deletion = actions.delete_sample(sha256, user_id, "legal request 42", actor="unittest")

    assert deletion.sha256 == sha256
    assert json.loads(deletion.rule_uuids) == sorted([RULE_UUID, OTHER_RULE_UUID])
    assert deletion.capture_count == 2
    assert deletion.reason == "legal request 42"
    assert deletion.purged_at is not None
    assert _captures_of(sha256) == []
    assert get_db().execute(select(SVSSampleRetirement).where(SVSSampleRetirement.sha256 == sha256)).first() is None
    # the file is purged, audited by the CAS too; the records are released for GC
    assert not svs_pool.exists(sha256)
    purge = get_db().execute(select(CASPurge).where(CASPurge.digest == sha256)).scalar_one()
    assert (purge.actor, purge.reason) == ("unittest", "svs sample deletion: legal request 42")
    assert all(svs_pool.exists(digest) and svs_pool.holds(digest) == [] for digest in records)
    # nothing else is touched
    assert len(_captures_of(other)) == 1 and svs_pool.exists(other)

    # deleting again returns the audit row
    assert actions.delete_sample(sha256, user_id, "again", actor="unittest").reason == "legal request 42"


def test_a_match_record_another_capture_holds_is_kept(user_id, svs_pool):
    record = b"the same match record"
    sha256 = _stored_sample(svs_pool, [RULE_UUID], b"svs delete one", record=record)
    other = _stored_sample(svs_pool, [RULE_UUID], b"svs keep the other", record=record)
    (kept,) = _captures_of(other)

    actions.delete_sample(sha256, user_id, "privacy", actor="unittest")

    assert svs_pool.holds(kept.record_digest) == [capture_hold(kept.id)]


def test_a_file_under_legal_hold_is_not_deleted(user_id, svs_pool):
    sha256 = _stored_sample(svs_pool, [RULE_UUID], b"svs legal hold")
    svs_pool.hold(sha256, Hold.legal("case-7"))

    with pytest.raises(LegalHoldActive):
        actions.delete_sample(sha256, user_id, "privacy", actor="unittest")

    assert len(_captures_of(sha256)) == 1
    assert _deletion(sha256) is None
    assert svs_pool.exists(sha256)


def test_a_file_on_another_nodes_local_pool_is_not_deleted_here(user_id, svs_pool):
    sha256 = _stored_sample(svs_pool, [RULE_UUID], b"svs other node")
    with private_transaction() as session:
        session.execute(update(SVSYaraCapture).where(SVSYaraCapture.sha256 == sha256).values(node="other_node"))

    with pytest.raises(WrongNode) as error:
        actions.delete_sample(sha256, user_id, "privacy", actor="unittest")

    assert error.value.node == "other_node"
    assert len(_captures_of(sha256)) == 1
    assert _deletion(sha256) is None


def test_an_unfinished_purge_is_retried(user_id, svs_pool, monkeypatch):
    sha256 = _stored_sample(svs_pool, [RULE_UUID], b"svs purge fails")
    real_purge = CASPool.purge

    def failing_purge(self, digest, **kwargs):
        raise OSError("backend unavailable")

    monkeypatch.setattr(CASPool, "purge", failing_purge)
    deletion = actions.delete_sample(sha256, user_id, "privacy", actor="unittest")
    assert deletion.purged_at is None
    assert _captures_of(sha256) == []
    assert svs_pool.exists(sha256)

    monkeypatch.setattr(CASPool, "purge", real_purge)
    deletion = actions.delete_sample(sha256, user_id, "a second reason", actor="unittest")
    assert deletion.purged_at is not None
    assert deletion.reason == "privacy"
    assert not svs_pool.exists(sha256)


def test_delete_needs_a_reason_and_a_sample(user_id):
    with pytest.raises(ValueError):
        actions.delete_sample("ab" * 32, user_id, " ", actor="unittest")
    with pytest.raises(SampleNotFound):
        actions.delete_sample("ab" * 32, user_id, "privacy", actor="unittest")


def test_a_missing_capture_is_deleted_too(user_id):
    sha256 = "cd" * 32
    insert_capture(str(uuid.uuid4()), sha256, state="missing", missing_reason="file", stored_at=None)
    deletion = actions.delete_sample(sha256, user_id, "privacy", actor="unittest")
    assert deletion.capture_count == 1
    assert deletion.purged_at is not None
    assert _captures_of(sha256) == []


def test_deletions_page(user_id):
    for content in (b"first deleted", b"second deleted", b"third deleted"):
        _, files = graded_alert("DELIVERY", {"a.bin": [RULE_UUID]}, contents={"a.bin": content})
        actions.delete_sample(_sha256(files), user_id, "privacy", actor="unittest")

    first = actions.deletions_page(None, None, 2)
    assert len(first) == 2
    rest = actions.deletions_page(None, (first[-1].updated_at, first[-1].id), 2)
    assert len(rest) == 1
    assert {row.sha256 for row in first + rest} == {row.sha256 for row in actions.deletions_page(None, None, 10)}
    assert actions.deletions_page(datetime.now() + timedelta(days=1), None, 10) == []


#
# capture honours deletions
#

def _captured(root_analysis, svs_pool):
    _file = add_file(root_analysis, "sample.bin", b"svs captured then deleted")
    add_yara_match(_file)
    (candidate,) = candidates_from_root(root_analysis)
    return candidate


def test_a_deleted_file_is_not_captured_again(root_analysis, svs_pool, user_id):
    candidate = _captured(root_analysis, svs_pool)
    assert capture(svs_pool, root_analysis.uuid, candidate).status == CaptureStatus.STORED
    actions.delete_sample(candidate.sha256, user_id, "privacy", actor="unittest")

    result = capture(svs_pool, str(uuid.uuid4()), candidate)

    assert (result.status, result.capture_id) == (CaptureStatus.DELETED, None)
    assert capture_rows() == []
    assert not svs_pool.exists(candidate.sha256)


def test_a_capture_that_raced_a_deletion_removes_what_it_wrote(root_analysis, svs_pool, monkeypatch):
    candidate = _captured(root_analysis, svs_pool)
    # the deletion commits after the capture's first check and before its second
    answers = iter([False, True])
    monkeypatch.setattr(capture_module, "is_deleted", lambda sha256: next(answers))

    result = capture(svs_pool, root_analysis.uuid, candidate)

    assert result.status == CaptureStatus.DELETED
    assert capture_rows() == []
    assert not svs_pool.exists(candidate.sha256)
