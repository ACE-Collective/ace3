import os

import pytest

from saq.collectors.hunter.service import MAX_SUBMISSIONS_PER_COLLECTION, HunterCollector
from tests.saq.helpers import create_staged_submission, create_submission_file_manager


@pytest.fixture
def file_manager(tmpdir):
    return create_submission_file_manager(tmpdir)


@pytest.mark.unit
def test_collect_drains_staged_submissions(file_manager):
    """a single call to collect() returns everything already staged

    the collection loop processes one collect() call per iteration, so yielding a single
    submission per call made a burst of hunt results drain one-per-loop-iteration"""
    staged = [create_staged_submission(file_manager) for _ in range(5)]

    collector = HunterCollector(file_manager)
    collected = list(collector.collect())

    assert sorted(_.root.uuid for _ in collected) == sorted(staged)


@pytest.mark.unit
def test_collect_stops_at_maximum(file_manager):
    """collect() yields at most MAX_SUBMISSIONS_PER_COLLECTION so the collection loop
    keeps coming back around to report status and check for shutdown"""
    for _ in range(MAX_SUBMISSIONS_PER_COLLECTION + 5):
        create_staged_submission(file_manager)

    collector = HunterCollector(file_manager)
    assert len(list(collector.collect())) == MAX_SUBMISSIONS_PER_COLLECTION

    # nothing is consumed by collecting - a submission leaves the staging directory only when it
    # reaches a terminal outcome, which is what makes it survive a crash mid-processing
    assert len(file_manager.list_staged_submissions()) == MAX_SUBMISSIONS_PER_COLLECTION + 5

    # and because a pass leaves work behind, the collection loop must run again immediately
    # rather than waiting collection_frequency
    assert collector.collect_until_empty


@pytest.mark.unit
def test_collect_empty_staging(file_manager):
    """an empty staging directory yields nothing"""
    collector = HunterCollector(file_manager)
    assert list(collector.collect()) == []


@pytest.mark.unit
def test_staged_submission_round_trips_metadata(file_manager):
    """key, group_assignments, group_value and queued_at survive the trip through disk

    these live on Submission in memory but must be read back after a restart, so they are
    stored on the root where they get serialized"""
    root_uuid = create_staged_submission(
        file_manager, key="dedup-key", group_value="1.2.3.4", group_assignments=["group_a"])

    collector = HunterCollector(file_manager)
    collected = list(collector.collect())

    assert len(collected) == 1
    submission = collected[0]
    assert submission.root.uuid == root_uuid
    assert submission.key == "dedup-key"
    assert submission.group_value == "1.2.3.4"
    assert submission.group_assignments == ["group_a"]
    assert submission.queued_time is not None
    assert submission.queue_age >= 0


@pytest.mark.unit
def test_incomplete_submissions_are_never_collected(file_manager):
    """a submission still being built is invisible until the rename commits it"""
    incomplete_dir = file_manager.get_staging_tmp_path("incomplete-uuid")
    os.makedirs(incomplete_dir)

    collector = HunterCollector(file_manager)
    assert list(collector.collect()) == []

    # and it is cleaned up at startup rather than accumulating
    assert file_manager.purge_incomplete_staging() == 1
    assert not os.path.exists(incomplete_dir)


@pytest.mark.unit
def test_unloadable_submission_is_quarantined(file_manager):
    """a corrupt staged submission is moved aside instead of wedging collection

    without this it would fail to load on every pass forever, and because collect() yields in
    directory order it would block everything behind it"""
    good_uuid = create_staged_submission(file_manager)

    # a directory that looks staged but has no readable root
    bad_uuid = "00000000-0000-0000-0000-000000000000"
    os.makedirs(file_manager.get_staging_path(bad_uuid))

    collector = HunterCollector(file_manager)
    collected = list(collector.collect())

    assert [_.root.uuid for _ in collected] == [good_uuid]
    assert file_manager.list_staged_submissions() == [good_uuid]
    assert os.path.isdir(os.path.join(file_manager.error_dir, bad_uuid))


@pytest.mark.unit
def test_discard_removes_staged_submission(file_manager):
    """terminal outcomes that never reach the incoming dir must still leave staging

    tuned_out and duplicate submissions are dropped by process_submission; without an explicit
    discard they would be collected again on every pass"""
    root_uuid = create_staged_submission(file_manager)
    assert file_manager.list_staged_submissions() == [root_uuid]

    assert file_manager.discard_staged_submission(root_uuid)
    assert file_manager.list_staged_submissions() == []
