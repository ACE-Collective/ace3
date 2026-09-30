import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from saq.cas import CASPool, Hold
from saq.configuration.config import get_config
from saq.environment import get_global_runtime_settings
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.yara_qa import store
from saq.yara_qa.store import (
    QARecordStatus,
    record_qa_match,
    serialize_match_record,
    summarize_match_record,
)
from tests.saq.yara_qa.conftest import (
    QA_UUID,
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

    result = record_qa_match(match_result, file_observable, root_analysis.uuid)
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
    first = record_qa_match(qa_match_result(), file_observable, root_analysis.uuid)
    (before,) = match_rows()

    second = record_qa_match(qa_match_result(), file_observable, root_analysis.uuid)
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
    record_qa_match(qa_match_result(commit=VERSION_A), file_observable, root_analysis.uuid)
    result = record_qa_match(qa_match_result(commit=VERSION_B), file_observable, root_analysis.uuid)
    assert result.status == QARecordStatus.STORED
    assert [row.signature_version for row in match_rows()] == [VERSION_A, VERSION_B]


def test_per_version_cap(make_file, root_analysis):
    cap = get_config().yara_qa.max_files_per_version
    results = [record_qa_match(qa_match_result(), make_file(), root_analysis.uuid) for _ in range(cap + 2)]

    assert [r.status for r in results] == [QARecordStatus.STORED] * cap + [QARecordStatus.CAPPED] * 2
    assert len(match_rows()) == cap

    # every match is counted, only the capped number is stored
    counters = counter_row()
    assert (counters.match_count, counters.stored_count) == (cap + 2, cap)


def test_per_signature_ceiling_across_versions(make_file, root_analysis):
    config = get_config().yara_qa
    assert config.max_files_per_version < config.max_files_per_signature < 2 * config.max_files_per_version

    for _ in range(config.max_files_per_version):
        assert record_qa_match(qa_match_result(commit=VERSION_A), make_file(), root_analysis.uuid).status == QARecordStatus.STORED

    remaining = config.max_files_per_signature - config.max_files_per_version
    statuses = [record_qa_match(qa_match_result(commit=VERSION_B), make_file(), root_analysis.uuid).status
                for _ in range(remaining + 1)]
    assert statuses == [QARecordStatus.STORED] * remaining + [QARecordStatus.CAPPED]

    # a third version gets nothing: the uuid is at its ceiling
    assert record_qa_match(qa_match_result(commit=VERSION_C), make_file(), root_analysis.uuid).status == QARecordStatus.CAPPED
    assert len(match_rows()) == config.max_files_per_signature
    assert counter_row(VERSION_C).match_count == 1


def test_missing_commit_is_the_unknown_version(make_file, root_analysis):
    record_qa_match(qa_match_result(commit=None), make_file(), root_analysis.uuid)
    (row,) = match_rows()
    assert row.signature_version == SIGNATURE_VERSION_UNKNOWN


@pytest.mark.parametrize("signature_uuid", [None, "", "   ", "x" * 37])
def test_rule_without_a_usable_uuid_is_skipped(make_file, root_analysis, signature_uuid):
    result = record_qa_match(qa_match_result(signature_uuid=signature_uuid), make_file(), root_analysis.uuid)
    assert result.status == QARecordStatus.SKIPPED
    assert match_rows() == []
    assert counter_row() is None


def test_missing_pool_is_skipped(make_file, root_analysis, monkeypatch):
    monkeypatch.setattr(get_config().yara_qa, "pool", "no_such_pool")
    result = record_qa_match(qa_match_result(), make_file(), root_analysis.uuid)
    assert result.status == QARecordStatus.SKIPPED
    assert match_rows() == []


def test_failed_file_put_rolls_back(make_file, root_analysis, monkeypatch):
    def failing_put(self, src, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(CASPool, "put", failing_put)
    result = record_qa_match(qa_match_result(), make_file(), root_analysis.uuid)
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
    result = record_qa_match(qa_match_result(), file_observable, root_analysis.uuid)
    assert result.status == QARecordStatus.FAILED
    assert match_rows() == []
    assert counter_row().stored_count == 0
    assert _holds(qa_pool, file_observable.sha256_hash) == []


def test_large_match_record_is_stored_whole(qa_pool, make_file, root_analysis):
    strings = [(offset * 8, "$loose", b"MZ\x90\x00" * 4) for offset in range(5000)] + [(3, "$tight", b"x")]
    match_result = qa_match_result(strings=strings)
    record_qa_match(match_result, make_file(), root_analysis.uuid)

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
    record_qa_match(qa_match_result(), file_observable, root_analysis.uuid)
    (row,) = match_rows()

    # the holds lapsed and GC collected both objects before the prune removed the row
    qa_pool.purge(row.sha256, reason="unittest", actor="unittest")
    qa_pool.purge(row.match_digest, reason="unittest", actor="unittest")

    result = record_qa_match(qa_match_result(), file_observable, root_analysis.uuid)
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
    record_qa_match(qa_match_result(), file_observable, root_analysis.uuid)

    original_renew = store._renew
    calls = []

    def renew_misses_once(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            # as if the row did not exist yet when this worker looked
            return None
        return original_renew(*args, **kwargs)

    monkeypatch.setattr(store, "_renew", renew_misses_once)
    result = record_qa_match(qa_match_result(), file_observable, root_analysis.uuid)
    assert result.status == QARecordStatus.RENEWED
    assert len(calls) == 2

    (row,) = match_rows()
    assert row.hit_count == 2
    counters = counter_row()
    assert (counters.match_count, counters.stored_count) == (2, 1)


@pytest.mark.unit
def test_summary_of_string_match_objects():
    """Newer yara-python returns StringMatch objects with instances instead of tuples."""
    match_result = {
        "rule": "r", "namespace": "n", "commit": None, "tags": [], "meta": {},
        "strings": [
            SimpleNamespace(identifier="$a", instances=[SimpleNamespace(offset=40), SimpleNamespace(offset=90)]),
            SimpleNamespace(identifier="$b", instances=[]),
        ],
    }
    summary = summarize_match_record(match_result)
    assert summary["string_match_count"] == 2
    assert summary["strings"] == [
        {"identifier": "$a", "count": 2, "first_offset": 40},
        {"identifier": "$b", "count": 0, "first_offset": None},
    ]
