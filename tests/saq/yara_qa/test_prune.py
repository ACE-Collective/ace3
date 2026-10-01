import pytest

from saq.configuration.config import get_config
from saq.yara_qa.prune import prune_expired
from saq.yara_qa.store import QATarget, record_qa_match
from tests.saq.yara_qa.conftest import VERSION_A, VERSION_B, counter_row, expire_matches, match_rows, qa_match_result

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
