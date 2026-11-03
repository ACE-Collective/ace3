import json
import logging
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from saq.cas import CASPool, Hold
from saq.configuration.config import get_config
from saq.database.model import YaraQAMatch, YaraQASignature
from saq.database.private_session import private_transaction
from saq.environment import get_global_runtime_settings
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.yara_qa import store
from saq.yara_qa.store import QARecordStatus, QATarget, QAVersionKind, record_qa_match
from saq.yara_scanning.match_record import serialize_match_record
from tests.saq.yara_qa.conftest import (
    QA_UUID,
    RULE_HASH_1,
    RULE_HASH_2,
    VERSION_A,
    VERSION_B,
    VERSION_C,
    counter_row,
    match_rows,
    qa_match_result,
)

pytestmark = pytest.mark.integration


def _holds(pool: CASPool, digest: str) -> list[Hold]:
    return pool.holds(digest)


def test_stores_file_and_full_record(qa_pool, make_file, root_analysis):
    file_observable = make_file()
    match_result = qa_match_result()

    result = record_qa_match(match_result, QATarget.from_file_observable(file_observable, root_analysis.uuid))
    assert result.status == QARecordStatus.STORED

    (row,) = match_rows()
    assert row.id == result.match_id
    assert row.signature_version == VERSION_A
    assert row.sha256 == file_observable.sha256_hash
    assert row.file_name == file_observable.file_name
    assert row.file_size == file_observable.size
    assert row.root_uuid == root_analysis.uuid
    assert row.observable_uuid == file_observable.uuid
    assert row.node == get_global_runtime_settings().saq_node
    assert row.hit_count == 1

    # the expiry is retention_days out, and the holds on both objects carry the same one
    retention = timedelta(days=get_config().yara_qa.retention_days)
    assert abs(row.expires_at - (datetime.now() + retention)) < timedelta(minutes=1)
    for digest in (row.sha256, row.match_digest):
        (hold,) = _holds(qa_pool, digest)
        assert (hold.holder_kind, hold.holder_id) == ("yara_qa", str(row.id))
        assert hold.expires_at == row.expires_at

    with qa_pool.open(row.sha256) as fp:
        assert fp.read() == open(file_observable.full_path, "rb").read()

    with qa_pool.open(row.match_digest) as fp:
        assert fp.read() == serialize_match_record(match_result)

    summary = json.loads(row.match_summary)
    assert summary["rule"] == "qa_rule"
    assert summary["string_match_count"] == 3
    assert summary["strings"] == [
        {"identifier": "$a", "count": 2, "first_offset": 0},
        {"identifier": "$b", "count": 1, "first_offset": 5},
    ]

    counters = counter_row()
    assert (counters.rule_name, counters.match_count, counters.stored_count) == ("qa_rule", 1, 1)


def test_rematch_renews_instead_of_storing_again(qa_pool, make_file, root_analysis):
    file_observable = make_file()
    first = record_qa_match(qa_match_result(), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    (before,) = match_rows()

    second = record_qa_match(qa_match_result(), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    assert second.status == QARecordStatus.RENEWED
    assert second.match_id == first.match_id

    (after,) = match_rows()
    assert after.hit_count == 2
    assert after.expires_at >= before.expires_at
    assert after.last_seen >= before.last_seen
    (hold,) = _holds(qa_pool, after.sha256)
    assert hold.expires_at == after.expires_at

    counters = counter_row()
    assert (counters.match_count, counters.stored_count) == (2, 1)


def test_same_file_under_a_new_version_is_a_new_match(make_file, root_analysis):
    file_observable = make_file()
    record_qa_match(qa_match_result(commit=VERSION_A), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    result = record_qa_match(qa_match_result(commit=VERSION_B), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    assert result.status == QARecordStatus.STORED
    assert [row.signature_version for row in match_rows()] == [VERSION_A, VERSION_B]


def test_per_version_cap(make_file, root_analysis):
    cap = get_config().yara_qa.max_files_per_version
    results = [record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid)) for _ in range(cap + 2)]

    assert [r.status for r in results] == [QARecordStatus.STORED] * cap + [QARecordStatus.CAPPED] * 2
    assert len(match_rows()) == cap

    # every match is counted, only the capped number is stored
    counters = counter_row()
    assert (counters.match_count, counters.stored_count) == (cap + 2, cap)


def test_per_signature_ceiling_across_versions(make_file, root_analysis):
    config = get_config().yara_qa
    assert config.max_files_per_version < config.max_files_per_signature < 2 * config.max_files_per_version

    for _ in range(config.max_files_per_version):
        assert record_qa_match(qa_match_result(commit=VERSION_A), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status == QARecordStatus.STORED

    remaining = config.max_files_per_signature - config.max_files_per_version
    statuses = [record_qa_match(qa_match_result(commit=VERSION_B), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status
                for _ in range(remaining + 1)]
    assert statuses == [QARecordStatus.STORED] * remaining + [QARecordStatus.CAPPED]

    # a third version gets nothing: the uuid is at its ceiling
    assert record_qa_match(qa_match_result(commit=VERSION_C), QATarget.from_file_observable(make_file(), root_analysis.uuid)).status == QARecordStatus.CAPPED
    assert len(match_rows()) == config.max_files_per_signature
    assert counter_row(VERSION_C).match_count == 1


def test_missing_commit_is_the_unknown_version(make_file, root_analysis):
    record_qa_match(qa_match_result(commit=None), QATarget.from_file_observable(make_file(), root_analysis.uuid))
    (row,) = match_rows()
    assert row.signature_version == SIGNATURE_VERSION_UNKNOWN


def test_a_commit_that_does_not_touch_the_rule_keeps_its_version(make_file, root_analysis):
    file_observable = make_file()
    first = record_qa_match(qa_match_result(commit=VERSION_A, rule_content_hash=RULE_HASH_1),
                            QATarget.from_file_observable(file_observable, root_analysis.uuid))
    second = record_qa_match(qa_match_result(commit=VERSION_B, rule_content_hash=RULE_HASH_1),
                             QATarget.from_file_observable(file_observable, root_analysis.uuid))

    assert (first.status, second.status) == (QARecordStatus.STORED, QARecordStatus.RENEWED)
    (row,) = match_rows()
    assert (row.signature_version, row.version_kind, row.hit_count) == (RULE_HASH_1, QAVersionKind.CONTENT, 2)

    counters = counter_row(RULE_HASH_1)
    assert (counters.version_kind, counters.match_count, counters.stored_count) == (QAVersionKind.CONTENT, 2, 1)
    assert (counters.first_commit, counters.last_commit) == (VERSION_A, VERSION_B)
    assert counter_row(VERSION_A) is None and counter_row(VERSION_B) is None


def test_a_changed_rule_is_a_new_version(make_file, root_analysis):
    file_observable = make_file()
    record_qa_match(qa_match_result(rule_content_hash=RULE_HASH_1), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    result = record_qa_match(qa_match_result(rule_content_hash=RULE_HASH_2), QATarget.from_file_observable(file_observable, root_analysis.uuid))

    assert result.status == QARecordStatus.STORED
    assert [row.signature_version for row in match_rows()] == [RULE_HASH_1, RULE_HASH_2]


def test_a_match_without_a_content_hash_is_filed_under_its_commit(make_file, root_analysis):
    record_qa_match(qa_match_result(commit=VERSION_A, rule_content_hash=None),
                    QATarget.from_file_observable(make_file(), root_analysis.uuid))

    (row,) = match_rows()
    assert (row.signature_version, row.version_kind) == (VERSION_A, QAVersionKind.COMMIT)
    counters = counter_row(VERSION_A)
    assert (counters.version_kind, counters.first_commit, counters.last_commit) == (QAVersionKind.COMMIT, VERSION_A, VERSION_A)


@pytest.mark.parametrize("signature_uuid", [None, "", "   ", "x" * 37])
def test_rule_without_a_usable_uuid_is_skipped(make_file, root_analysis, signature_uuid):
    result = record_qa_match(qa_match_result(signature_uuid=signature_uuid), QATarget.from_file_observable(make_file(), root_analysis.uuid))
    assert result.status == QARecordStatus.SKIPPED
    assert match_rows() == []
    assert counter_row() is None


def test_missing_pool_is_skipped(make_file, root_analysis, monkeypatch):
    monkeypatch.setattr(get_config().yara_qa, "pool", "no_such_pool")
    result = record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid))
    assert result.status == QARecordStatus.SKIPPED
    assert match_rows() == []


def test_failed_file_put_rolls_back(make_file, root_analysis, monkeypatch):
    def failing_put(self, src, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(CASPool, "put", failing_put)
    result = record_qa_match(qa_match_result(), QATarget.from_file_observable(make_file(), root_analysis.uuid))
    assert result.status == QARecordStatus.FAILED
    assert match_rows() == []

    # counted, but the slot was given back
    counters = counter_row()
    assert (counters.match_count, counters.stored_count) == (1, 0)


def test_failed_record_put_rolls_back_and_releases_the_file(qa_pool, make_file, root_analysis, monkeypatch):
    original_put = CASPool.put
    calls = []

    def put_file_only(self, src, **kwargs):
        calls.append(src)
        if len(calls) == 2:
            raise OSError("disk full")
        return original_put(self, src, **kwargs)

    monkeypatch.setattr(CASPool, "put", put_file_only)
    file_observable = make_file()
    result = record_qa_match(qa_match_result(), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    assert result.status == QARecordStatus.FAILED
    assert match_rows() == []
    assert counter_row().stored_count == 0
    assert _holds(qa_pool, file_observable.sha256_hash) == []


def test_large_match_record_is_stored_whole(qa_pool, make_file, root_analysis):
    strings = [(offset * 8, "$loose", b"MZ\x90\x00" * 4) for offset in range(5000)] + [(3, "$tight", b"x")]
    match_result = qa_match_result(strings=strings)
    record_qa_match(match_result, QATarget.from_file_observable(make_file(), root_analysis.uuid))

    (row,) = match_rows()
    with qa_pool.open(row.match_digest) as fp:
        record = fp.read()

    assert record == serialize_match_record(match_result)
    assert len(json.loads(record)["strings"]) == 5001

    # the summary holds counts, not the matches
    summary = json.loads(row.match_summary)
    assert summary["string_match_count"] == 5001
    assert summary["strings"] == [
        {"identifier": "$loose", "count": 5000, "first_offset": 0},
        {"identifier": "$tight", "count": 1, "first_offset": 3},
    ]
    assert len(row.match_summary) < 1024


def test_rematch_restores_objects_that_are_gone(qa_pool, make_file, root_analysis):
    file_observable = make_file()
    record_qa_match(qa_match_result(), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    (row,) = match_rows()

    # the holds lapsed and GC collected both objects before the prune removed the row
    qa_pool.purge(row.sha256, reason="unittest", actor="unittest")
    qa_pool.purge(row.match_digest, reason="unittest", actor="unittest")

    result = record_qa_match(qa_match_result(), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    assert result.status == QARecordStatus.RENEWED

    (after,) = match_rows()
    assert qa_pool.exists(after.sha256)
    assert qa_pool.exists(after.match_digest)
    assert [h.holder_id for h in _holds(qa_pool, after.sha256)] == [str(row.id)]
    assert [h.holder_id for h in _holds(qa_pool, after.match_digest)] == [str(row.id)]


def test_losing_the_insert_race_renews_the_winner(make_file, root_analysis, monkeypatch):
    """Two workers store the same file for the same version at once: the second one's insert hits
    the unique key, its transaction (and so its slot reservation) rolls back, and it renews the
    first one's row instead."""
    file_observable = make_file()
    record_qa_match(qa_match_result(), QATarget.from_file_observable(file_observable, root_analysis.uuid))

    original_renew = store._renew
    calls = []

    def renew_misses_once(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            # as if the row did not exist yet when this worker looked
            return None
        return original_renew(*args, **kwargs)

    monkeypatch.setattr(store, "_renew", renew_misses_once)
    result = record_qa_match(qa_match_result(), QATarget.from_file_observable(file_observable, root_analysis.uuid))
    assert result.status == QARecordStatus.RENEWED
    assert len(calls) == 2

    (row,) = match_rows()
    assert row.hit_count == 2
    counters = counter_row()
    assert (counters.match_count, counters.stored_count) == (2, 1)


#
# rolling over superseded versions (unittest caps: 3 per version, 5 per uuid)
#

RULE_HASH_3 = "3" * 64


def _store(make_file, root_analysis, rule_hash: str):
    return record_qa_match(qa_match_result(rule_content_hash=rule_hash),
                           QATarget.from_file_observable(make_file(), root_analysis.uuid))


def _last_matched(signature_version: str, ago: timedelta) -> None:
    """Move a version's last match into the past, as the database sees time."""
    with private_transaction() as session:
        session.execute(
            update(YaraQASignature)
            .where(YaraQASignature.signature_uuid == QA_UUID, YaraQASignature.signature_version == signature_version)
            .values(last_match_at=datetime.now() - ago)
            .execution_options(synchronize_session=False))


def _last_seen(match_id: int, ago: timedelta) -> None:
    with private_transaction() as session:
        session.execute(
            update(YaraQAMatch).where(YaraQAMatch.id == match_id)
            .values(last_seen=datetime.now() - ago).execution_options(synchronize_session=False))


def _versions() -> dict[str, int]:
    result: dict[str, int] = {}
    for row in match_rows():
        result[row.signature_version] = result.get(row.signature_version, 0) + 1
    return result


@pytest.fixture
def full_rule(make_file, root_analysis) -> list[int]:
    """Rule hash 1 with three files that last matched three hours ago, and rule hash 2 with two
    files that last matched two hours ago: the uuid is at its ceiling of 5. Returns rule hash 1's
    match ids, the file seen longest ago first.

    Rule hash 2's files are stored first, one of them was seen longest ago of all, and rule hash 1's
    are seen longer ago the higher their id, so deleting in id order, or by last_seen alone, picks
    other files than the documented order does."""
    config = get_config().yara_qa
    assert (config.max_files_per_version, config.max_files_per_signature) == (3, 5)

    second = [_store(make_file, root_analysis, RULE_HASH_2).match_id for _ in range(2)]
    first = [_store(make_file, root_analysis, RULE_HASH_1).match_id for _ in range(3)]
    for n, match_id in enumerate(first):
        _last_seen(match_id, timedelta(hours=3, minutes=n))
    _last_seen(second[0], timedelta(hours=5))
    _last_matched(RULE_HASH_1, timedelta(hours=3))
    _last_matched(RULE_HASH_2, timedelta(hours=2))
    return list(reversed(first))


def test_a_superseded_version_rolls_over_to_make_room(qa_pool, make_file, root_analysis, full_rule, caplog):
    evicted = next(row for row in match_rows() if row.id == full_rule[0])

    with caplog.at_level(logging.INFO):
        result = _store(make_file, root_analysis, RULE_HASH_3)

    assert result.status == QARecordStatus.STORED
    # the oldest version gives up the file it saw longest ago
    assert _versions() == {RULE_HASH_1: 2, RULE_HASH_2: 2, RULE_HASH_3: 1}
    assert full_rule[0] not in {row.id for row in match_rows()}
    assert (counter_row(RULE_HASH_1).stored_count, counter_row(RULE_HASH_3).stored_count) == (2, 1)
    assert _holds(qa_pool, evicted.sha256) == []
    # the match record is the same for every match here, so other rows still hold it
    assert str(evicted.id) not in {h.holder_id for h in _holds(qa_pool, evicted.match_digest)}

    (record,) = [r for r in caplog.records if r.getMessage().startswith("rolled over yara qa match")]
    assert (record.match_id, record.evicted_signature_version, record.signature_version) == (
        evicted.id, RULE_HASH_1, RULE_HASH_3)


def test_each_new_file_rolls_over_one_file(make_file, root_analysis, full_rule):
    statuses = [_store(make_file, root_analysis, RULE_HASH_3).status for _ in range(4)]

    # the third file fills the new version's own cap; rollover never makes room past it
    assert statuses == [QARecordStatus.STORED] * 3 + [QARecordStatus.CAPPED]
    assert _versions() == {RULE_HASH_2: 2, RULE_HASH_3: 3}


def test_a_version_that_matched_within_the_hour_is_not_rolled_over(make_file, root_analysis, full_rule):
    _last_matched(RULE_HASH_1, timedelta(minutes=30))
    _last_matched(RULE_HASH_2, timedelta(minutes=50))

    assert _store(make_file, root_analysis, RULE_HASH_3).status == QARecordStatus.CAPPED
    assert _versions() == {RULE_HASH_1: 3, RULE_HASH_2: 2}


def test_the_current_versions_own_cap_does_not_roll_over(make_file, root_analysis):
    for _ in range(2):
        _store(make_file, root_analysis, RULE_HASH_1)
    for _ in range(3):
        _store(make_file, root_analysis, RULE_HASH_2)
    _last_matched(RULE_HASH_1, timedelta(hours=3))

    assert _store(make_file, root_analysis, RULE_HASH_2).status == QARecordStatus.CAPPED
    assert _versions() == {RULE_HASH_1: 2, RULE_HASH_2: 3}


def test_rollover_skips_files_another_transaction_holds(make_file, root_analysis, full_rule):
    superseded = [row.id for row in match_rows()]
    with private_transaction() as locker:
        locker.execute(select(YaraQAMatch.id).where(YaraQAMatch.id.in_(superseded)).with_for_update()).all()

        # does not wait on the locks
        assert _store(make_file, root_analysis, RULE_HASH_3).status == QARecordStatus.CAPPED

    assert _versions() == {RULE_HASH_1: 3, RULE_HASH_2: 2}


def test_a_failed_hold_release_still_rolls_over(make_file, root_analysis, full_rule, monkeypatch, caplog):
    def release_fails(self, digest, hold):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(CASPool, "release", release_fails)
    with caplog.at_level(logging.WARNING):
        assert _store(make_file, root_analysis, RULE_HASH_3).status == QARecordStatus.STORED

    assert full_rule[0] not in {row.id for row in match_rows()}
    assert any(r.getMessage().startswith("unable to release yara qa hold") and f"match {full_rule[0]}" in r.getMessage()
               for r in caplog.records)


def test_nothing_rolls_over_when_storing_is_turned_off(make_file, root_analysis, full_rule, monkeypatch):
    # a ceiling of 0 stores nothing, so deleting an old file would only lose it
    monkeypatch.setattr(get_config().yara_qa, "max_files_per_signature", 0)

    assert _store(make_file, root_analysis, RULE_HASH_3).status == QARecordStatus.CAPPED
    assert _versions() == {RULE_HASH_1: 3, RULE_HASH_2: 2}
