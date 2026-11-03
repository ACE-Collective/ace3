import logging

import pytest
from sqlalchemy import select, update

from saq.cas import CASPool, Hold, get_cas
from saq.configuration.config import get_config
from saq.database.model import YaraQAMatch
from saq.database.private_session import private_transaction
from saq.yara_qa import prune
from saq.yara_qa.prune import prune_expired, purge_matches
from saq.yara_qa.store import QATarget, record_qa_match
from tests.saq.yara_qa.conftest import (
    QA_UUID,
    VERSION_A,
    VERSION_B,
    counter_row,
    expire_matches,
    match_rows,
    qa_match_result,
)

pytestmark = pytest.mark.integration


def test_prune_removes_expired_matches_in_batches(qa_pool, make_file, root_analysis):
    # 3 under one version and 2 under another: the per-signature ceiling in the tests is 5
    for version, count in ((VERSION_A, 3), (VERSION_B, 2)):
        for _ in range(count):
            assert record_qa_match(qa_match_result(commit=version), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status == "stored"

    rows = match_rows()
    assert len(rows) == 5
    expired, kept = rows[:4], rows[4:]
    expire_matches([row.id for row in expired])

    dry = prune_expired(dry_run=True)
    assert (dry.expired, dry.deleted) == (4, 0)
    assert len(match_rows()) == 5

    stats = prune_expired()
    batch_size = get_config().yara_qa.prune_batch_size
    assert stats.deleted == 4
    # a full last batch takes one more (empty) pass to find out it was the last
    assert stats.batches == -(-4 // batch_size)
    assert stats.release_failures == 0
    assert [row.id for row in match_rows()] == [row.id for row in kept]

    # the slots are given back, the match counts are history and stay
    assert (counter_row(VERSION_A).stored_count, counter_row(VERSION_A).match_count) == (0, 3)
    assert (counter_row(VERSION_B).stored_count, counter_row(VERSION_B).match_count) == (1, 2)

    # the holds of the pruned matches are gone, the kept match still holds its objects. (the
    # synthetic match records here are identical, so they are one deduplicated object that the kept
    # match still holds)
    for row in expired:
        assert qa_pool.holds(row.sha256) == []
        assert str(row.id) not in [h.holder_id for h in qa_pool.holds(row.match_digest)]
    assert [h.holder_id for h in qa_pool.holds(kept[0].sha256)] == [str(kept[0].id)]

    assert prune_expired().deleted == 0


def test_a_pruned_slot_can_be_used_again(make_file, root_analysis):
    cap = get_config().yara_qa.max_files_per_version
    for _ in range(cap):
        record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid))
    assert record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status == "capped"

    expire_matches([match_rows()[0].id])
    prune_expired()
    assert record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status == "stored"


#
# purging
#

OTHER_UUID = "6b1d8a2f-2d54-4b4a-9e9f-3a2c4d5e6f70"


def _store(make_file, root_analysis, version: str = VERSION_A, signature_uuid: str = QA_UUID, file_observable=None):
    result = record_qa_match(qa_match_result(signature_uuid=signature_uuid, commit=version),
                             QATarget.from_file_observable(file_observable or make_file(), root_analysis.uuid))
    assert result.status == "stored"
    return result.match_id


def test_purge_by_version(qa_pool, make_file, root_analysis):
    purged = [_store(make_file, root_analysis, VERSION_A) for _ in range(3)]
    kept = [_store(make_file, root_analysis, VERSION_B) for _ in range(2)]
    purged_rows = [row for row in match_rows() if row.id in purged]

    stats = purge_matches(QA_UUID, versions=[VERSION_A])

    assert (stats.deleted, stats.remaining, stats.release_failures) == (3, 0, 0)
    assert [row.id for row in match_rows()] == kept
    assert (counter_row(VERSION_A).stored_count, counter_row(VERSION_A).match_count) == (0, 3)
    assert counter_row(VERSION_B).stored_count == 2
    for row in purged_rows:
        assert qa_pool.holds(row.sha256) == []


def test_purge_by_match_ids_only_touches_its_signature(make_file, root_analysis):
    mine = [_store(make_file, root_analysis) for _ in range(2)]
    other = _store(make_file, root_analysis, signature_uuid=OTHER_UUID)

    stats = purge_matches(QA_UUID, match_ids=[mine[0], other])

    assert stats.deleted == 1
    assert [row.id for row in match_rows()] == [mine[1]]
    assert [row.id for row in match_rows(OTHER_UUID)] == [other]


def test_purge_leaves_rows_another_transaction_holds(make_file, root_analysis):
    ids = [_store(make_file, root_analysis) for _ in range(3)]
    with private_transaction() as locker:
        locker.execute(select(YaraQAMatch.id).where(YaraQAMatch.id == ids[0]).with_for_update()).all()

        # does not wait on the lock
        stats = purge_matches(QA_UUID, versions=[VERSION_A])

    assert (stats.deleted, stats.remaining) == (2, 1)
    assert [row.id for row in match_rows()] == [ids[0]]


def test_purge_leaves_a_match_whose_puts_are_in_flight(make_file, root_analysis):
    ids = [_store(make_file, root_analysis) for _ in range(2)]
    with private_transaction() as session:
        session.execute(update(YaraQAMatch).where(YaraQAMatch.id == ids[0]).values(match_digest=None)
                        .execution_options(synchronize_session=False))

    stats = purge_matches(QA_UUID, versions=[VERSION_A])

    assert (stats.deleted, stats.remaining) == (1, 0)
    assert [row.id for row in match_rows()] == [ids[0]]


def test_purge_keeps_every_other_hold_on_the_file(qa_pool, make_file, root_analysis):
    file_observable = make_file()
    purged = _store(make_file, root_analysis, VERSION_A, file_observable=file_observable)
    kept = _store(make_file, root_analysis, VERSION_B, file_observable=file_observable)
    svs_pool = get_cas().pool("svs_samples")
    svs_hold = Hold("svs_capture", "1")
    svs_pool.put(file_observable.full_path, hold=svs_hold, digest=file_observable.sha256_hash)

    assert purge_matches(QA_UUID, versions=[VERSION_A]).deleted == 1

    # the other version's row still holds the file in the yara_qa pool, and SVS's hold is in
    # another pool, which a purge never touches
    assert [h.holder_id for h in qa_pool.holds(file_observable.sha256_hash)] == [str(kept)]
    assert qa_pool.exists(file_observable.sha256_hash)
    assert [(h.holder_kind, h.holder_id) for h in svs_pool.holds(file_observable.sha256_hash)] == [("svs_capture", "1")]
    assert purged not in [row.id for row in match_rows()]


def test_a_purged_slot_can_be_used_again(make_file, root_analysis):
    cap = get_config().yara_qa.max_files_per_version
    ids = [_store(make_file, root_analysis) for _ in range(cap)]
    assert record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status == "capped"

    purge_matches(QA_UUID, match_ids=[ids[0]])
    assert record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status == "stored"


@pytest.mark.parametrize("targets", [{}, {"versions": [VERSION_A], "match_ids": [1]}])
def test_purge_needs_exactly_one_target(targets):
    with pytest.raises(ValueError):
        purge_matches(QA_UUID, **targets)


def test_purging_nothing_is_not_an_error(make_file, root_analysis):
    _store(make_file, root_analysis)
    assert purge_matches(QA_UUID, versions=[]).deleted == 0
    assert purge_matches(QA_UUID, match_ids=[]).deleted == 0
    assert len(match_rows()) == 1


def test_a_purge_that_fails_partway_logs_what_it_removed(make_file, root_analysis, monkeypatch, caplog):
    for _ in range(2):
        _store(make_file, root_analysis)

    real_transaction = prune.private_transaction
    calls = []

    def fails_after_the_batch():
        # the first transaction deletes the batch; the second, the remaining count, fails
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("the database went away")
        return real_transaction()

    monkeypatch.setattr(prune, "private_transaction", fails_after_the_batch)
    with caplog.at_level(logging.INFO), pytest.raises(RuntimeError):
        purge_matches(QA_UUID, versions=[VERSION_A])

    assert match_rows() == []
    (record,) = [r for r in caplog.records if r.getMessage().startswith("purge of yara qa matches of signature")]
    assert (record.levelno, record.signature_uuid, record.deleted) == (logging.WARNING, QA_UUID, 2)


def test_a_purge_whose_hold_releases_fail_still_removes_the_rows(make_file, root_analysis, monkeypatch, caplog):
    ids = [_store(make_file, root_analysis) for _ in range(2)]

    def release_fails(self, digest, hold):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(CASPool, "release", release_fails)
    with caplog.at_level(logging.WARNING):
        stats = purge_matches(QA_UUID, versions=[VERSION_A])

    # the holds expire on their own; the rows and their slots are gone now
    assert (stats.deleted, stats.remaining, stats.release_failures) == (2, 0, 2)
    assert match_rows() == []
    assert counter_row(VERSION_A).stored_count == 0
    warned = {r.getMessage() for r in caplog.records if r.getMessage().startswith("unable to release yara qa hold")}
    assert all(any(f"match {match_id}" in message for message in warned) for match_id in ids)
